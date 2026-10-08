-- Shadow mode: flows are validated, scored and stored, but raise no cases/tickets. Used for sources
-- (like the live sensor) whose detections are not yet calibrated.
ALTER TABLE flow_events ADD COLUMN shadow boolean NOT NULL DEFAULT false;
