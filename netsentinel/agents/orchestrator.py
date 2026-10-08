"""Security Orchestrator: correlates attack detections into cases and dispatches the next agent.

detection.attack --(same source IP + family)--> case (open) --(quiet / old / large)--> investigating
                                                                 -> investigation.requested

A case stays 'open' while flows keep arriving, so the investigation sees the whole burst instead
of its first flow. Grouping by source is also what exposes behaviour no single flow shows
(a scan is many tiny flows from one host).

Run one orchestrator at a time; the unique open-case index makes a second one fail loudly
rather than create duplicate cases.
"""

import logging
import signal
import threading
from collections import defaultdict

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .. import bus as busmod

log = logging.getLogger(__name__)

INVESTIGATION_REQUESTED = "investigation.requested"
QUIET_SECONDS = 30        # no new flows for this long -> the burst is over
MAX_OPEN_SECONDS = 120    # long-running attacks get a first investigation after 2 minutes
MAX_OPEN_FLOWS = 1000     # ... or once they are this large
CONTINUATION_SECONDS = 900
RETRY_UNAVAILABLE_AFTER_SECONDS = 900   # Claude was down or rate-limited: try the explanation again later
MAX_INVESTIGATIONS_PER_CASE = 3  # later flows of the same source+family within 15 min join the same case


class Orchestrator:
    name = "orchestrator"

    def __init__(self, pool: ConnectionPool, bus: busmod.Bus | None = None, *, batch_size: int = 1000):
        self.pool, self.bus, self.batch_size = pool, bus or busmod.PostgresBus(), batch_size
        self.stop_event = threading.Event()

    def correlate(self) -> int:
        with self.pool.connection() as conn, conn.transaction():
            msgs = self.bus.poll(conn, self.name, busmod.DETECTION_ATTACK, self.batch_size)
            if not msgs:
                return 0
            ids = [m.payload["event_id"] for m in msgs]
            rows = conn.execute(
                "SELECT d.event_id, host(f.src_ip), d.family, d.p_attack, coalesce(f.observed_at, f.received_at) "
                "FROM detections d JOIN flow_events f USING (event_id) WHERE d.event_id = ANY(%s::uuid[])",
                (ids,)).fetchall()
            groups = defaultdict(list)
            for event_id, src, family, p, ts in rows:
                groups[(src, family)].append((event_id, p, ts))
            for (src, family), items in groups.items():
                key = f"{src or 'unknown'}|{family or 'Unknown'}"
                first, last = min(i[2] for i in items), max(i[2] for i in items)
                # The open case for this key; else a recent case already sent on (a long attack must stay
                # one case and one ticket, not a new case every MAX_OPEN_FLOWS flows); else a new case.
                case = conn.execute(
                    "SELECT case_id FROM cases WHERE correlation_key = %s AND status <> 'closed' "
                    "AND (status = 'open' OR last_seen >= %s - make_interval(secs => %s)) "
                    "ORDER BY (status = 'open') DESC, last_seen DESC LIMIT 1 FOR UPDATE",
                    (key, first, CONTINUATION_SECONDS)).fetchone()
                if case:
                    case_id = case[0]
                else:
                    case_id = conn.execute(
                        "INSERT INTO cases (correlation_key, src_ip, family, first_seen, last_seen) "
                        "VALUES (%s, %s, %s, %s, %s) RETURNING case_id", (key, src, family, first, last)).fetchone()[0]
                    conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'open', %s, %s)",
                                 (case_id, self.name, Jsonb({"correlation_key": key})))
                    log.info("case %s opened for %s", case_id, key)
                # ON CONFLICT: redelivered messages (at-least-once bus) are not double counted
                added = conn.execute(
                    "INSERT INTO case_events (case_id, event_id) SELECT %s, unnest(%s::uuid[]) "
                    "ON CONFLICT (event_id) DO NOTHING RETURNING event_id",
                    (case_id, [i[0] for i in items])).fetchall()
                conn.execute(
                    "UPDATE cases SET flow_count = flow_count + %s, first_seen = least(first_seen, %s), "
                    "last_seen = greatest(last_seen, %s), max_p_attack = greatest(max_p_attack, %s), updated_at = now() "
                    "WHERE case_id = %s", (len(added), first, last, max(i[1] for i in items), case_id))
            self.bus.commit(conn, self.name, busmod.DETECTION_ATTACK, msgs[-1].id)
            return len(msgs)

    def merge_duplicates(self, actor: str) -> list[tuple[str, int]]:
        """One-off repair: cases with the same key still waiting for investigation are merged into the
        oldest one; the others are closed (the Investigation Agent skips closed cases)."""
        merged = []
        with self.pool.connection() as conn, conn.transaction():
            keys = conn.execute("SELECT correlation_key FROM cases WHERE status = 'investigating' "
                                "GROUP BY 1 HAVING count(*) > 1").fetchall()
            for (key,) in keys:
                ids = [r[0] for r in conn.execute(
                    "SELECT case_id FROM cases WHERE correlation_key = %s AND status = 'investigating' "
                    "ORDER BY created_at FOR UPDATE", (key,))]
                keep, dupes = ids[0], ids[1:]
                conn.execute("UPDATE case_events SET case_id = %s WHERE case_id = ANY(%s)", (keep, dupes))
                conn.execute(
                    "UPDATE cases c SET flow_count = s.n, first_seen = s.lo, last_seen = s.hi, max_p_attack = s.p, "
                    "updated_at = now() FROM (SELECT count(*) n, min(coalesce(f.observed_at, f.received_at)) lo, "
                    "max(coalesce(f.observed_at, f.received_at)) hi, max(d.p_attack) p FROM case_events ce "
                    "JOIN flow_events f USING (event_id) JOIN detections d USING (event_id) WHERE ce.case_id = %s) s "
                    "WHERE c.case_id = %s", (keep, keep))
                conn.execute("UPDATE cases SET status = 'closed', flow_count = 0, updated_at = now() WHERE case_id = ANY(%s)",
                             (dupes,))
                for d in dupes:
                    conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'closed', %s, %s)",
                                 (d, actor, Jsonb({"merged_into": str(keep)})))
                merged.append((key, len(dupes)))
        return merged

    def dispatch(self) -> list:
        with self.pool.connection() as conn, conn.transaction():
            ready = conn.execute(
                "UPDATE cases SET status = 'investigating', updated_at = now() WHERE case_id IN ("
                "  SELECT case_id FROM cases WHERE status = 'open' AND ("
                "    updated_at < now() - make_interval(secs => %s) OR created_at < now() - make_interval(secs => %s)"
                "    OR flow_count >= %s) FOR UPDATE SKIP LOCKED) "
                "RETURNING case_id, correlation_key, flow_count",
                (QUIET_SECONDS, MAX_OPEN_SECONDS, MAX_OPEN_FLOWS)).fetchall()
            retry = conn.execute(
                "UPDATE cases SET status = 'investigating', updated_at = now() WHERE case_id IN ("
                "  SELECT c.case_id FROM cases c JOIN LATERAL (SELECT llm_status, created_at FROM investigations i "
                "    WHERE i.case_id = c.case_id ORDER BY created_at DESC LIMIT 1) last ON true "
                "  WHERE c.status IN ('investigated', 'assessed', 'ticketed') AND last.llm_status = 'unavailable' "
                "  AND last.created_at < now() - make_interval(secs => %s) "
                "  AND (SELECT count(*) FROM investigations i WHERE i.case_id = c.case_id) < %s "
                "  FOR UPDATE OF c SKIP LOCKED) RETURNING case_id, correlation_key, flow_count",
                (RETRY_UNAVAILABLE_AFTER_SECONDS, MAX_INVESTIGATIONS_PER_CASE)).fetchall()
            for case_id, key, _ in retry:
                log.info("case %s (%s): previous investigation had no LLM analysis; retrying", case_id, key)
            ready = ready + retry
            for case_id, key, n in ready:
                conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'investigating', %s, %s)",
                             (case_id, self.name, Jsonb({"flow_count": n})))
                self.bus.publish(conn, INVESTIGATION_REQUESTED, {"case_id": str(case_id)}, producer=self.name)
                log.info("case %s (%s, %d flows) -> investigation", case_id, key, n)
            return [r[0] for r in ready]

    def run(self, idle_sleep: float = 1.0) -> None:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: self.stop_event.set())
        log.info("orchestrator started")
        while not self.stop_event.is_set():
            try:
                n = self.correlate()
                self.dispatch()
            except Exception:
                log.exception("orchestrator cycle failed; retrying")
                n = 0
            if n < self.batch_size:
                self.stop_event.wait(idle_sleep)
        log.info("orchestrator stopped")
