"""Operator CLI. Key management is local-only (needs the Wall socket), never exposed over HTTP.

  netsentinel migrate
  netsentinel keys register --key-id ID --sha256 HEX --name NAME [--scopes ingest:write,events:read] [--expires-days N]
  netsentinel keys list
  netsentinel keys revoke KEY_ID --reason TEXT
  netsentinel serve [--host 127.0.0.1] [--port 8200]
  netsentinel models register MODEL_ID ARTIFACT_PATH | list | approve MODEL_ID | reject MODEL_ID | activate MODEL_ID
  netsentinel agent detection|orchestrator|investigation|risk|response|ticket [--once]
  netsentinel responses list [--all] | approve ACTION_ID --note N | reject ACTION_ID --note N | complete ACTION_ID --note N
  netsentinel tickets list [--all] | show TICKET_ID | assign TICKET_ID ASSIGNEE | resolve|close TICKET_ID --resolution R
  netsentinel assets add CIDR --name N --criticality 1-5 [--role R] [--owner O] | list | seed-cicids-lab
  netsentinel zones add CIDR --zone internal|dmz|external [--note N] | list
  netsentinel cases list [--limit 20] | show CASE_ID
  netsentinel replay [--limit 5000] [--rate 0] [--batch-size 500] [--seed 0] [--url http://127.0.0.1:8200]
"""

import argparse
import getpass
import sys
from datetime import datetime, timedelta, timezone

from . import db, migrate, registry, site
from .security import api_keys


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(v, list):
        return ",".join(v)
    return str(v)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netsentinel")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    keys = sub.add_parser("keys").add_subparsers(dest="action", required=True)
    reg = keys.add_parser("register", help="register a key by its SHA-256 digest (the key itself is never sent)")
    reg.add_argument("--key-id", required=True)
    reg.add_argument("--sha256", required=True)
    reg.add_argument("--name", required=True)
    reg.add_argument("--scopes", default="ingest:write,events:read")
    reg.add_argument("--expires-days", type=int)
    keys.add_parser("list")
    gr = keys.add_parser("grant", help="add a permission to an active key (e.g. actions:decide)")
    gr.add_argument("key_id")
    gr.add_argument("scope")
    rev = keys.add_parser("revoke")
    rev.add_argument("key_id")
    rev.add_argument("--reason", required=True)
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8200)
    srv.add_argument("--dashboard-only", action="store_true", help="serve only /dashboard (for a public listener)")
    srv.add_argument("--tls-cert", help="PEM certificate; serves HTTPS when given with --tls-key")
    srv.add_argument("--tls-key", help="PEM private key")
    models = sub.add_parser("models").add_subparsers(dest="action", required=True)
    mreg = models.add_parser("register")
    mreg.add_argument("model_id")
    mreg.add_argument("artifact_path", help="relative to the project root, under artifacts/")
    models.add_parser("list")
    for verb in ("approve", "reject", "activate"):
        models.add_parser(verb).add_argument("model_id")
    agent = sub.add_parser("agent")
    agent.add_argument("name", choices=["detection", "orchestrator", "investigation", "risk", "response", "ticket"])
    resp = sub.add_parser("responses", help="human review of proposed response actions").add_subparsers(
        dest="action", required=True)
    resp.add_parser("list").add_argument("--all", action="store_true", help="include decided actions")
    for verb in ("approve", "reject", "complete"):
        v = resp.add_parser(verb)
        v.add_argument("action_id")
        v.add_argument("--note", required=True, help="why (recorded in the audit trail)")
    tk = sub.add_parser("tickets").add_subparsers(dest="action", required=True)
    tk.add_parser("list").add_argument("--all", action="store_true", help="include resolved/closed")
    tk.add_parser("show").add_argument("ticket_id")
    ta = tk.add_parser("assign")
    ta.add_argument("ticket_id")
    ta.add_argument("assignee")
    for verb in ("resolve", "close"):
        v = tk.add_parser(verb)
        v.add_argument("ticket_id")
        v.add_argument("--resolution", required=True)
    assets = sub.add_parser("assets").add_subparsers(dest="action", required=True)
    aadd = assets.add_parser("add")
    aadd.add_argument("cidr")
    aadd.add_argument("--name", required=True)
    aadd.add_argument("--criticality", type=int, required=True, choices=range(1, 6))
    aadd.add_argument("--role", default="")
    aadd.add_argument("--owner", default="")
    assets.add_parser("list")
    assets.add_parser("seed-cicids-lab", help="DEMO: the published CICIDS-2017 testbed layout, for replays only")
    zones = sub.add_parser("zones").add_subparsers(dest="action", required=True)
    zadd = zones.add_parser("add")
    zadd.add_argument("cidr")
    zadd.add_argument("--zone", required=True, choices=["internal", "dmz", "external"])
    zadd.add_argument("--note", default="")
    zones.add_parser("list")
    agent.add_argument("--once", action="store_true", help="process one batch and exit")
    cases = sub.add_parser("cases").add_subparsers(dest="action", required=True)
    cases.add_parser("list").add_argument("--limit", type=int, default=20)
    cases.add_parser("show").add_argument("case_id")
    cases.add_parser("merge-duplicates", help="merge same-key cases still waiting for investigation")
    e2e = sub.add_parser("e2e", help="end-to-end validation of the live pipeline")
    e2e.add_argument("--flows", type=int, default=400)
    e2e.add_argument("--seed", type=int, default=99)
    e2e.add_argument("--timeout", type=float, default=1800, help="seconds to wait for all cases to be ticketed")
    e2e.add_argument("--url", default="http://127.0.0.1:8200")
    sn = sub.add_parser("sensor", help="capture this host's traffic as flows and send them to the API")
    sn.add_argument("--interface", default=None, help="default: interface in config/site.json")
    sn.add_argument("--url", default="http://127.0.0.1:8200")
    sn.add_argument("--alert", action="store_true", help="raise cases/tickets (default: shadow mode, score only)")
    cal = sub.add_parser("calibrate", help="measure live-sensor detections against weak labels from host logs")
    cal.add_argument("--hours", type=float, default=24)
    cal.add_argument("--owner-ip", action="append", help="your own address(es); default: owner_ips in config/site.json")
    cal.add_argument("--host-ip", action="append", help="this host's address(es); default: auto-detected")
    cal.add_argument("--target-fpr", type=float, default=0.001)
    rp = sub.add_parser("replay", help="stream held-out CICIDS-2017 flows through the API and measure detections")
    rp.add_argument("--limit", type=int, default=5000)
    rp.add_argument("--rate", type=float, default=0, help="flows per second (0 = as fast as possible)")
    rp.add_argument("--batch-size", type=int, default=500)
    rp.add_argument("--seed", type=int, default=0)
    rp.add_argument("--timeout", type=float, default=300, help="seconds to wait for the Detection Agent")
    rp.add_argument("--url", default="http://127.0.0.1:8200")
    rp.add_argument("--slice", nargs=3, metavar=("DAY", "START_UTC", "MINUTES"),
                    help="replay every flow of a real capture interval in order, e.g. friday 16:55 10")
    a = p.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        if a.host not in ("127.0.0.1", "::1", "localhost") and not (a.dashboard_only and a.tls_cert and a.tls_key):
            print("error: a non-local listener must be --dashboard-only with --tls-cert/--tls-key", file=sys.stderr)
            return 2
        target = "netsentinel.api.main:dashboard_app" if a.dashboard_only else "netsentinel.api.main:app"
        uvicorn.run(target, factory=a.dashboard_only, host=a.host, port=a.port, proxy_headers=False,
                    server_header=False, ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key,
                    # TLS 1.2: forward-secret AEAD suites only (no CBC/RC4/3DES); TLS 1.3 suites are all AEAD
                    ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20")
        return 0
    if a.cmd == "agent":
        return _run_agent(a)
    if a.cmd == "sensor":
        import logging
        from . import sensor
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        sensor.run(interface=a.interface or site.load()["interface"], base_url=a.url, alert=a.alert)
        return 0
    if a.cmd == "calibrate":
        import json
        from . import calibrate
        r = calibrate.run(hours=a.hours, owner_ips=tuple(a.owner_ip or site.load()["owner_ips"]),
                          host_ips=tuple(a.host_ip or calibrate.host_addresses()), target_fpr=a.target_fpr)
        print(json.dumps(r, indent=2))
        return 0
    if a.cmd == "e2e":
        import json
        import logging
        from . import e2e
        logging.basicConfig(level=logging.WARNING)
        r = e2e.run(base_url=a.url, flows=a.flows, seed=a.seed, timeout=a.timeout)
        print(json.dumps(r, indent=2, default=str))
        return 0 if r["passed"] else 1
    if a.cmd == "replay":
        import json
        import logging
        from . import replay
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        result = replay.run(base_url=a.url, limit=a.limit, seed=a.seed, batch_size=a.batch_size,
                            rate=a.rate, timeout=a.timeout,
                            slice_spec=(a.slice[0], a.slice[1], float(a.slice[2])) if a.slice else None)
        print(json.dumps(result, indent=2, default=str))
        return 0

    with db.connect() as conn:
        if a.cmd == "models":
            return _models(conn, a)
        if a.cmd == "cases":
            return _cases(conn, a)
        if a.cmd in ("assets", "zones"):
            return _inventory(conn, a)
        if a.cmd == "responses":
            return _responses(conn, a)
        if a.cmd == "tickets":
            return _tickets(conn, a)
        if a.cmd == "migrate":
            applied = migrate.apply(conn)
            print("applied: " + (", ".join(applied) if applied else "nothing (up to date)"))
        elif a.action == "register":
            expires = datetime.now(timezone.utc) + timedelta(days=a.expires_days) if a.expires_days else None
            try:
                api_keys.register(conn, key_id=a.key_id, sha256_hex=a.sha256, name=a.name,
                                  scopes=[s.strip() for s in a.scopes.split(",") if s.strip()],
                                  created_by=getpass.getuser(), expires_at=expires)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(f"registered key {a.key_id} ({a.name}); only its SHA-256 digest is stored")
        elif a.action == "list":
            cols = ("key_id", "name", "scopes", "created_at", "expires_at", "last_used_at", "revoked_at")
            for k in api_keys.list_keys(conn):
                print("  ".join(f"{c}={_fmt(k[c])}" for c in cols))
        elif a.action == "grant":
            try:
                ok = api_keys.grant(conn, a.key_id, a.scope, actor=getpass.getuser())
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(f"{a.key_id}: granted {a.scope}" if ok else "no active key with that id, or it already has the scope")
            return 0 if ok else 1
        elif a.action == "revoke":
            ok = api_keys.revoke(conn, a.key_id, reason=a.reason, actor=getpass.getuser())
            print("revoked" if ok else "no active key with that id")
            return 0 if ok else 1
    return 0


def _models(conn, a) -> int:
    actor = getpass.getuser()
    try:
        if a.action == "register":
            info = registry.register(conn, a.model_id, a.artifact_path, actor=actor)
            print(f"registered candidate {info['model_id']} sha256={info['sha256']} schema={info['schema_version']}")
        elif a.action == "list":
            for m in registry.list_models(conn):
                print(f"{m['model_id']}  status={m['status']}  sha256={m['sha256'][:12]}…  approved_by={_fmt(m['approved_by'])}"
                      f"  activated_at={_fmt(m['activated_at'])}  thresholds={m['metrics'].get('thresholds')}")
        else:
            getattr(registry, a.action)(conn, a.model_id, actor=actor)
            past = {"approve": "approved", "reject": "rejected", "activate": "activated"}[a.action]
            print(f"{a.model_id}: {past} by {actor}")
    except (ValueError, registry.ModelCheckFailed) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def _cases(conn, a) -> int:
    import json
    if a.action == "merge-duplicates":
        from .agents.orchestrator import Orchestrator
        pool = db.make_pool(max_size=1)
        try:
            for key, n in Orchestrator(pool).merge_duplicates(actor=f"human:{getpass.getuser()}"):
                print(f"{key}: merged {n} duplicate case(s) into the oldest")
        finally:
            pool.close()
        return 0
    if a.action == "list":
        for r in conn.execute("SELECT case_id, status, correlation_key, flow_count, first_seen, last_seen FROM cases "
                              "ORDER BY created_at DESC LIMIT %s", (a.limit,)):
            print(f"{r[0]}  {r[1]:<13} {r[2]:<32} flows={r[3]:<6} {_fmt(r[4])} .. {_fmt(r[5])}")
        return 0
    inv = conn.execute("SELECT telemetry, model_output, analysis, recommendations, llm_status, guard_findings, llm_model "
                       "FROM investigations WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (a.case_id,)).fetchone()
    if not inv:
        print("no investigation yet for this case")
        return 1
    sections = [("VERIFIED TELEMETRY", inv[0]), ("MODEL OUTPUT", inv[1]),
                (f"LLM ANALYSIS ({inv[6] or 'none'}, status={inv[4]})", inv[2]), ("RECOMMENDATION", inv[3]),
                ("GUARD FINDINGS", inv[5])]
    risk = conn.execute("SELECT score, severity, factors, requires_review, review_reasons, rules_version "
                        "FROM risk_assessments WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (a.case_id,)).fetchone()
    if risk:
        sections.append((f"RISK ASSESSMENT ({risk[5]}): {risk[0]}/100 {risk[1].upper()}"
                         + (" - REVIEW REQUIRED" if risk[3] else ""), {"factors": risk[2], "review_reasons": risk[4]}))
    for title, body in sections:
        print(f"\n=== {title} ===\n{json.dumps(body, indent=2, default=str)}")
    return 0


CICIDS_LAB = {  # published CICIDS-2017 testbed (UNB CIC); demo context for replays, not a real network
    "assets": [("192.168.10.3/32", "lab-dc01", "Windows Server 2016 domain controller + DNS", 5),
               ("192.168.10.50/32", "lab-web01", "Ubuntu 16 web server (public-facing)", 4),
               ("192.168.10.51/32", "lab-srv02", "Ubuntu 12 server (public-facing)", 4)]
              + [(f"192.168.10.{h}/32", f"lab-ws-{h}", "workstation", 2) for h in (5, 8, 9, 12, 14, 15, 16, 17, 19, 25)],
    "zones": [("192.168.10.0/24", "internal", "lab victim network"),
              ("172.16.0.0/16", "external", "lab firewall outside interface (attacker NAT)"),
              ("205.174.165.0/24", "external", "lab attacker network")],
}


def _inventory(conn, a) -> int:
    actor = getpass.getuser()
    if a.cmd == "assets" and a.action == "add":
        conn.execute("INSERT INTO assets (cidr, name, role, criticality, owner, source) VALUES (%s, %s, %s, %s, %s, %s) "
                     "ON CONFLICT (cidr) DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role, "
                     "criticality = EXCLUDED.criticality, owner = EXCLUDED.owner, source = EXCLUDED.source",
                     (a.cidr, a.name, a.role, a.criticality, a.owner, f"operator:{actor}"))
        print(f"asset {a.cidr} = {a.name} (criticality {a.criticality})")
    elif a.cmd == "assets" and a.action == "seed-cicids-lab":
        with conn.transaction():
            for cidr, name, role, crit in CICIDS_LAB["assets"]:
                conn.execute("INSERT INTO assets (cidr, name, role, criticality, source) VALUES (%s, %s, %s, %s, "
                             "'demo:cicids-2017-lab') ON CONFLICT (cidr) DO NOTHING", (cidr, name, role, crit))
            for cidr, zone, note in CICIDS_LAB["zones"]:
                conn.execute("INSERT INTO network_zones (cidr, zone, note, source) VALUES (%s, %s, %s, "
                             "'demo:cicids-2017-lab') ON CONFLICT (cidr) DO NOTHING", (cidr, zone, note))
        print(f"seeded {len(CICIDS_LAB['assets'])} demo assets and {len(CICIDS_LAB['zones'])} zones (source demo:cicids-2017-lab)")
    elif a.cmd == "assets":
        for r in conn.execute("SELECT cidr, name, criticality, role, source FROM assets ORDER BY criticality DESC, cidr"):
            print(f"{str(r[0]):<20} {r[1]:<14} crit={r[2]}  {r[3]}  [{r[4]}]")
    elif a.action == "add":
        conn.execute("INSERT INTO network_zones (cidr, zone, note, source) VALUES (%s, %s, %s, %s) "
                     "ON CONFLICT (cidr) DO UPDATE SET zone = EXCLUDED.zone, note = EXCLUDED.note, source = EXCLUDED.source",
                     (a.cidr, a.zone, a.note, f"operator:{actor}"))
        print(f"zone {a.cidr} = {a.zone}")
    else:
        for r in conn.execute("SELECT cidr, zone, note, source FROM network_zones ORDER BY cidr"):
            print(f"{str(r[0]):<20} {r[1]:<9} {r[2]}  [{r[3]}]")
    return 0


def _responses(conn, a) -> int:
    from .agents import response
    if a.action == "list":
        where = "" if a.all else "WHERE r.status IN ('proposed', 'approved')"
        for r in conn.execute(
                "SELECT r.action_id, r.status, r.action_type, r.target, r.disruptive, t.ticket_id, t.priority, r.cautions "
                f"FROM response_actions r LEFT JOIN tickets t USING (case_id) {where} "
                "ORDER BY t.priority NULLS LAST, r.proposed_at"):
            print(f"{r[0]}  {r[1]:<9} {r[6] or '--'} {r[5] or '-':<10} {r[2]:<31} {r[3]}"
                  f"{'  [DISRUPTIVE]' if r[4] else ''}")
            for c in r[7]:
                print(f"{'':<38}! {c}")
        return 0
    actor = f"human:{getpass.getuser()}"
    try:
        if a.action == "complete":
            res = response.complete(conn, a.action_id, actor=actor, note=a.note)
        else:
            res = response.decide(conn, a.action_id, approve=a.action == "approve", actor=actor, note=a.note)
    except (ValueError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"{res['action_type']} on {res['target']}: {res['status']} by {actor}")
    if res["status"] == "approved":
        print("NetSentinel does not execute actions. Carry it out with your own tools, then run "
              f"`netsentinel responses complete {a.action_id} --note ...`.")
    return 0


def _tickets(conn, a) -> int:
    import json
    from .agents import ticket
    actor = f"human:{getpass.getuser()}"
    try:
        if a.action == "list":
            where = "" if a.all else "WHERE status NOT IN ('resolved', 'closed')"
            for r in conn.execute("SELECT ticket_id, priority, status, needs_review, sla_due_at, assignee, title "
                                  f"FROM tickets {where} ORDER BY priority, sla_due_at"):
                overdue = " OVERDUE" if r[4] < datetime.now(timezone.utc) and r[2] not in ("resolved", "closed") else ""
                print(f"{r[0]}  {r[1]} {r[2]:<17} {'REVIEW ' if r[3] else '':<7} due {_fmt(r[4])}{overdue}  "
                      f"{r[5] or 'unassigned':<12} {r[6]}")
        elif a.action == "show":
            t = conn.execute("SELECT ticket_id, title, priority, status, assignee, sla_due_at, summary, resolution "
                             "FROM tickets WHERE ticket_id = %s", (a.ticket_id,)).fetchone()
            if not t:
                print("not found", file=sys.stderr)
                return 1
            print(f"{t[0]}  {t[1]}\npriority {t[2]}  status {t[3]}  assignee {t[4] or '-'}  due {_fmt(t[5])}")
            for section, body in t[6].items():
                print(f"\n=== {section} ===\n{json.dumps(body, indent=2, default=str)}")
            print("\n=== TIMELINE ===")
            for e in conn.execute("SELECT at, actor, event, detail FROM ticket_events WHERE ticket_id = %s ORDER BY id",
                                  (a.ticket_id,)):
                print(f"{_fmt(e[0])}  {e[1]:<20} {e[2]:<18} {json.dumps(e[3], default=str)}")
        elif a.action == "assign":
            ticket.assign(conn, a.ticket_id, actor=actor, assignee=a.assignee)
            print(f"{a.ticket_id} assigned to {a.assignee}")
        else:
            ticket.resolve(conn, a.ticket_id, actor=actor, resolution=a.resolution, close=a.action == "close")
            print(f"{a.ticket_id} {a.action}d")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def _run_agent(a) -> int:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    pool = db.make_pool(max_size=4)
    try:
        if a.name == "detection":
            from .agents.detection import DetectionAgent
            agent = DetectionAgent(pool)
            once = agent.process_batch
        elif a.name == "orchestrator":
            from .agents.orchestrator import Orchestrator
            agent = Orchestrator(pool)
            once = lambda: {"correlated": agent.correlate(), "dispatched": len(agent.dispatch())}
        elif a.name in ("response", "ticket"):
            from .agents.response import ResponseAgent
            from .agents.ticket import TicketAgent
            agent = (ResponseAgent if a.name == "response" else TicketAgent)(pool)
            once = lambda: {"processed": agent.process()}
        elif a.name == "risk":
            from .agents.risk import RiskAgent
            agent = RiskAgent(pool)
            once = lambda: {"assessed": agent.process()}
        else:
            from .agents.investigation import InvestigationAgent
            agent = InvestigationAgent(pool)
            once = lambda: {"investigated": agent.process()}
        if a.once:
            print(once())
        else:
            agent.run()
    finally:
        pool.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
