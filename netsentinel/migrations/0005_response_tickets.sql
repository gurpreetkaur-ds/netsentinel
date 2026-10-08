-- Response Agent proposals. NetSentinel never executes them: a human approves or rejects each one,
-- performs approved actions with their own tools, then marks them completed.
CREATE TABLE response_actions (
    action_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         uuid NOT NULL REFERENCES cases (case_id),
    assessment_id   uuid NOT NULL REFERENCES risk_assessments (assessment_id),
    action_type     text NOT NULL,
    target          text NOT NULL,
    params          jsonb NOT NULL DEFAULT '{}'::jsonb,
    rationale       text NOT NULL,
    disruptive      boolean NOT NULL,
    reversible      boolean NOT NULL CHECK (reversible),   -- only reversible actions may ever be proposed
    cautions        jsonb NOT NULL DEFAULT '[]'::jsonb,
    status          text NOT NULL DEFAULT 'proposed'
                        CHECK (status IN ('proposed', 'approved', 'rejected', 'completed')),
    proposed_at     timestamptz NOT NULL DEFAULT now(),
    decided_by      text CHECK (decided_by !~ '^agent:'),  -- agents can propose, never decide
    decided_at      timestamptz,
    decision_note   text,
    completed_by    text CHECK (completed_by !~ '^agent:'),
    completed_at    timestamptz,
    CHECK ((status = 'proposed') = (decided_by IS NULL)),
    CHECK ((status = 'completed') = (completed_by IS NOT NULL))
);
CREATE INDEX response_actions_case ON response_actions (case_id);
CREATE INDEX response_actions_pending ON response_actions (proposed_at) WHERE status = 'proposed';

CREATE FUNCTION response_actions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'response actions cannot be deleted';
    END IF;
    IF NEW.action_type <> OLD.action_type OR NEW.target <> OLD.target OR NEW.params <> OLD.params
       OR NEW.case_id <> OLD.case_id THEN
        RAISE EXCEPTION 'a proposed action cannot be altered; propose a new one';
    END IF;
    IF NOT ((OLD.status = 'proposed' AND NEW.status IN ('approved', 'rejected'))
            OR (OLD.status = 'approved' AND NEW.status = 'completed')) THEN
        RAISE EXCEPTION 'invalid response action transition % -> %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER response_actions_guard BEFORE UPDATE OR DELETE ON response_actions
    FOR EACH ROW EXECUTE FUNCTION response_actions_guard();

-- Ticket tracking: one ticket per case.
CREATE SEQUENCE ticket_number_seq;
CREATE TABLE tickets (
    ticket_id     text PRIMARY KEY DEFAULT 'NS-' || lpad(nextval('ticket_number_seq')::text, 6, '0'),
    case_id       uuid NOT NULL UNIQUE REFERENCES cases (case_id),
    title         text NOT NULL,
    severity      text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    priority      text NOT NULL CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    status        text NOT NULL DEFAULT 'new'
                      CHECK (status IN ('new', 'awaiting_approval', 'in_progress', 'resolved', 'closed')),
    needs_review  boolean NOT NULL DEFAULT false,
    assignee      text,
    sla_due_at    timestamptz NOT NULL,
    summary       jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    resolution    text,
    CHECK ((status IN ('resolved', 'closed')) = (resolved_at IS NOT NULL))
);
CREATE INDEX tickets_open ON tickets (priority, sla_due_at) WHERE status NOT IN ('resolved', 'closed');

CREATE TABLE ticket_events (
    id         bigserial PRIMARY KEY,
    ticket_id  text NOT NULL REFERENCES tickets (ticket_id),
    actor      text NOT NULL,
    event      text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ticket_events_ticket ON ticket_events (ticket_id, id);
CREATE TRIGGER ticket_events_append_only BEFORE UPDATE OR DELETE ON ticket_events
    FOR EACH ROW EXECUTE FUNCTION append_only();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
