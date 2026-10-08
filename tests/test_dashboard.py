import hashlib

import pytest
from fastapi.testclient import TestClient

from netsentinel.agents.response import ResponseAgent
from netsentinel.agents.risk import RiskAgent
from netsentinel.agents.ticket import TicketAgent
from netsentinel.api.app import create_app
from netsentinel.security import api_keys
from test_orchestration import FakeLLM, _good_output, _investigate, seeded  # noqa: F401  (fixture)


def _key(pool, scopes=("events:read",)):
    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                          name="dash-test", scopes=scopes, created_by="pytest")
    return key


@pytest.fixture
def client(pool):
    with TestClient(create_app(pool=pool), follow_redirects=False) as c:
        yield c


def _login(client, key):
    return client.post("/dashboard/login", content=f"api_key={key}",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_requires_sign_in(client):
    r = client.get("/dashboard")
    assert r.status_code == 303 and r.headers["location"] == "/dashboard/login"
    page = client.get("/dashboard/login")
    assert page.status_code == 200 and "default-src 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"


def test_sign_in_sets_hardened_cookie_and_shows_overview(client, pool):
    r = _login(client, _key(pool))
    assert r.status_code == 303
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/dashboard" in cookie
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Open tickets" in page.text and "Awaiting your approval" in page.text
    assert "<script>" not in page.text.replace('<script type="application/json" id="chart-data">', "")  # no inline JS


def test_wrong_scope_bad_key_and_cross_origin_are_refused(client, pool):
    assert _login(client, _key(pool, scopes=("ingest:write",))).status_code == 401
    assert _login(client, "nsk_000000000000_" + "A" * 43).status_code == 401
    r = client.post("/dashboard/login", content="api_key=x", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.example"})
    assert r.status_code == 403
    for origin, expected in (("null", 403), ("http://testserver", 401)):   # same origin passes the CSRF check
        r = client.post("/dashboard/login", content="api_key=x", headers={
            "Content-Type": "application/x-www-form-urlencoded", "Origin": origin})
        assert r.status_code == expected, origin


def test_revoked_key_or_tampered_cookie_ends_session(client, pool):
    key = _key(pool)
    _login(client, key)
    assert client.get("/dashboard").status_code == 200
    body, sig = client.cookies.get("ns_session").split(".")
    client.cookies.set("ns_session", f"{body}.{sig[:-2]}AA", path="/dashboard")
    assert client.get("/dashboard").status_code == 303
    client.cookies.clear()
    _login(client, key)
    with pool.connection() as c:
        api_keys.revoke(c, api_keys.parse_key_id(key), reason="test", actor="pytest")
    assert client.get("/dashboard").status_code == 303


def test_ticket_page_shows_labelled_sections_and_escapes_html(client, pool, seeded):
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    for agent in (RiskAgent(pool), ResponseAgent(pool), TicketAgent(pool)):
        while agent.process():
            pass
    with pool.connection() as c:
        tid = c.execute("SELECT ticket_id FROM tickets WHERE case_id = %s", (case_id,)).fetchone()[0]
        c.execute("UPDATE tickets SET title = '<script>alert(1)</script>' WHERE ticket_id = %s", (tid,))
    _login(client, _key(pool))
    page = client.get(f"/dashboard/tickets/{tid}")
    assert page.status_code == 200
    for label in ("VERIFIED TELEMETRY", "MODEL OUTPUT", "LLM ANALYSIS", "RECOMMENDATION"):
        assert label in page.text
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert client.get("/dashboard/tickets/NS-999999").status_code == 404


@pytest.mark.parametrize("name", ["../app.py", "..%2Fapp.py", "dashboard.py", "x.js"])
def test_static_is_allowlisted(client, name):
    assert client.get(f"/dashboard/static/{name}").status_code == 404


def test_static_assets_served(client):
    assert client.get("/dashboard/static/dashboard.js").headers["content-type"].startswith("text/javascript")
    assert client.get("/dashboard/static/chart.umd.min.js").status_code == 200


def test_dashboard_only_app_has_no_ingestion_api(pool):
    with TestClient(create_app(pool=pool, dashboard_only=True), follow_redirects=False) as c:
        assert c.get("/v1/whoami").status_code == 404
        assert c.post("/v1/flows", json={}).status_code == 404
        assert c.get("/v1/openapi.json").status_code == 404
        assert c.get("/dashboard/login").status_code == 200
        assert c.get("/").headers["location"] == "/dashboard"


def test_cli_refuses_public_listener_without_tls_and_dashboard_only(capsys):
    from netsentinel import cli
    assert cli.main(["serve", "--host", "0.0.0.0", "--port", "8443"]) == 2
    assert cli.main(["serve", "--host", "0.0.0.0", "--dashboard-only"]) == 2
    assert "non-local listener" in capsys.readouterr().err


def test_hsts_only_over_https(pool):
    with TestClient(create_app(pool=pool, dashboard_only=True), base_url="https://testserver") as c:
        assert c.get("/dashboard/login").headers["strict-transport-security"] == "max-age=31536000"
    with TestClient(create_app(pool=pool, dashboard_only=True)) as c:
        assert "strict-transport-security" not in c.get("/dashboard/login").headers


def _ticket_with_actions(pool, seeded):
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    for agent in (RiskAgent(pool), ResponseAgent(pool), TicketAgent(pool)):
        while agent.process():
            pass
    with pool.connection() as c:
        tid = c.execute("SELECT ticket_id FROM tickets WHERE case_id = %s", (case_id,)).fetchone()[0]
        aid = c.execute("SELECT action_id::text FROM response_actions WHERE case_id = %s AND status = 'proposed' LIMIT 1",
                        (case_id,)).fetchone()[0]
    return tid, aid


def _form(client, url, **fields):
    from urllib.parse import urlencode
    return client.post(url, content=urlencode(fields), headers={"Content-Type": "application/x-www-form-urlencoded"})


def _csrf(page_html):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', page_html).group(1)


def test_decisions_need_scope_csrf_and_the_same_key(client, pool, seeded):
    tid, aid = _ticket_with_actions(pool, seeded)
    reader = _key(pool)                                           # events:read only
    _login(client, reader)
    page = client.get(f"/dashboard/tickets/{tid}")
    assert 'name="csrf"' not in page.text                        # no decision forms without the permission

    decider = _key(pool, scopes=("events:read", "actions:decide"))
    other = _key(pool, scopes=("events:read", "actions:decide"))
    client.cookies.clear()
    _login(client, decider)
    page = client.get(f"/dashboard/tickets/{tid}")
    token = _csrf(page.text)
    url = f"/dashboard/actions/{aid}"
    assert _form(client, url, decision="approve", note="x", api_key=decider).status_code == 403          # no csrf
    assert _form(client, url, decision="approve", note="x", api_key=other, csrf=token).status_code == 403  # other key
    assert _form(client, url, decision="approve", note="x", api_key=reader, csrf=token).status_code == 403 # no scope
    assert _form(client, url, decision="approve", note="", api_key=decider, csrf=token).status_code == 422 # no note
    r = _form(client, url, decision="approve", note="verified scan", api_key=decider, csrf=token)
    assert r.status_code == 303 and r.headers["location"] == f"/dashboard/tickets/{tid}"
    with pool.connection() as c:
        status, by, note = c.execute("SELECT status, decided_by, decision_note FROM response_actions WHERE action_id = %s",
                                     (aid,)).fetchone()
    assert status == "approved" and by == "human:dash-test@dashboard" and note == "verified scan"
    assert _form(client, url, decision="reject", note="x", api_key=decider, csrf=token).status_code == 409
    assert _form(client, url, decision="complete", note="blocked in firewall", api_key=decider,
                 csrf=token).status_code == 303
    r = _form(client, f"/dashboard/tickets/{tid}/close", note="handled", api_key=decider, csrf=token)
    assert r.status_code == 303
    with pool.connection() as c:
        assert c.execute("SELECT status FROM tickets WHERE ticket_id = %s", (tid,)).fetchone() == ("closed",)


def test_decision_errors_render_html_for_browsers(client, pool, seeded):
    tid, aid = _ticket_with_actions(pool, seeded)
    decider = _key(pool, scopes=("events:read", "actions:decide"))
    _login(client, decider)
    r = client.post(f"/dashboard/actions/{aid}", content="decision=approve&note=x&api_key=wrong&csrf=bad",
                    headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"})
    assert r.status_code == 403 and "<html" in r.text and "Reload the page" in r.text


def test_grant_scope(pool):
    from netsentinel.security import api_keys as ak
    key = _key(pool)
    kid = ak.parse_key_id(key)
    with pool.connection() as c:
        assert ak.grant(c, kid, "actions:decide", actor="pytest")
        assert not ak.grant(c, kid, "actions:decide", actor="pytest")          # already has it
        assert c.execute("SELECT 'actions:decide' = ANY(scopes) FROM api_keys WHERE key_id = %s", (kid,)).fetchone()[0]


def test_presentation_download_requires_sign_in(client, pool):
    assert client.get("/dashboard/files/NetSentinel.pptx").status_code == 303
    _login(client, _key(pool))
    r = client.get("/dashboard/files/NetSentinel.pptx")
    assert r.status_code == 200 and r.content[:2] == b"PK" and "attachment" in r.headers["content-disposition"]
    assert client.get("/dashboard/files/..%2Fpyproject.toml").status_code == 404
    assert client.get("/dashboard/files/README.md").status_code == 404
