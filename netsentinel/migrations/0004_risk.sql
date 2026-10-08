-- ASSET INVENTORY: operator-maintained context. Risk scoring reads it; agents never write it.
CREATE TABLE assets (
    asset_id     bigserial PRIMARY KEY,
    cidr         cidr NOT NULL UNIQUE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    role         text NOT NULL DEFAULT '' CHECK (length(role) <= 100),
    criticality  smallint NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    owner        text NOT NULL DEFAULT '' CHECK (length(owner) <= 100),
    source       text NOT NULL DEFAULT 'operator',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE network_zones (
    cidr        cidr PRIMARY KEY,
    zone        text NOT NULL CHECK (zone IN ('internal', 'dmz', 'external')),
    note        text NOT NULL DEFAULT '',
    source      text NOT NULL DEFAULT 'operator'
);

-- Risk Assessment Agent output: a reproducible score with its full factor breakdown.
CREATE TABLE risk_assessments (
    assessment_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id           uuid NOT NULL REFERENCES cases (case_id),
    investigation_id  uuid REFERENCES investigations (investigation_id),
    score             smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
    severity          text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    factors           jsonb NOT NULL,
    requires_review   boolean NOT NULL,
    review_reasons    jsonb NOT NULL DEFAULT '[]'::jsonb,
    rules_version     text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX risk_assessments_case ON risk_assessments (case_id, created_at DESC);
CREATE INDEX risk_assessments_severity ON risk_assessments (severity, created_at DESC);
CREATE TRIGGER risk_assessments_append_only BEFORE UPDATE OR DELETE ON risk_assessments
    FOR EACH ROW EXECUTE FUNCTION append_only();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
