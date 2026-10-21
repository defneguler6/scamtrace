"""Crawl the synthetic sites through the API and check what a payment firm sees."""

import functools
import http.server
import importlib
import json
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

DEMO = Path(__file__).parent.parent / "demo"
sys.path.insert(0, str(DEMO))
sys.path.insert(0, str(Path(__file__).parent))


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def env(tmp_path_factory, monkeypatch_module):
    import make_sites
    make_sites.main()
    fx = json.loads((DEMO / "fixtures.json").read_text())
    servers = []
    for name, port in fx["ports"].items():
        h = functools.partial(_Quiet, directory=str(DEMO / "sites" / name))
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), h)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)

    tmp = tmp_path_factory.mktemp("st")
    monkeypatch_module.setenv("SCAMTRACE_DB", str(tmp / "t.db"))
    monkeypatch_module.setenv("SCAMTRACE_EVIDENCE", str(tmp / "ev"))
    import scamtrace.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app, headers={"X-API-Key": "demo-key"})

    crawled = {}
    for ad in fx["ads"]:
        body = {k: v for k, v in ad.items() if k != "site"}
        body["landing_url"] = f"http://127.0.0.1:{fx['ports'][ad['site']]}/index.html"
        crawled[ad["ad_id"]] = client.post("/v1/sightings/ad", json=body).json()
    for rep in fx["reports"]:
        client.post("/v1/sightings/report", json=rep)
    yield client, fx, crawled
    for s in servers:
        s.shutdown()


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def check(client, **q):
    return client.post("/v1/payee/check", json=q).json()


def test_crawler_reaches_payment_pages(env):
    _, _, crawled = env
    assert crawled["AD-1001"]["payment_page"].split("?")[0].endswith("deposit.html")
    assert {p["type"] for p in crawled["AD-1001"]["payment_details"]} == {"uk_account", "tron"}
    assert {p["type"] for p in crawled["AD-2001"]["payment_details"]} == {"uk_account", "iban"}
    assert crawled["AD-3001"]["payment_details"] == []  # legitimate shop


def test_one_kit_on_two_domains_is_one_campaign(env):
    _, _, crawled = env
    assert crawled["AD-1001"]["campaign_id"] == crawled["AD-1002"]["campaign_id"]
    assert crawled["AD-2001"]["campaign_id"] == crawled["AD-2002"]["campaign_id"]
    assert crawled["AD-1001"]["campaign_id"] != crawled["AD-2001"]["campaign_id"]


def test_payee_check_risks(env):
    client, fx, _ = env
    k = fx["known"]
    r = check(client, sort_code=k["uk_a"][0], account_number=k["uk_a"][1], direction="outbound")
    assert r["risk"] == "high" and r["campaign"]["scam_type"] == "investment"
    assert r["campaign"]["websites"] == 2 and r["campaign"]["victim_reports"] == 1
    assert check(client, iban=k["iban_c"])["risk"] == "high"
    assert check(client, wallet=k["tron"])["risk"] == "high"
    assert check(client, sort_code="00-33-44", account_number="12121212")["risk"] == "medium"
    assert check(client, sort_code="00-77-88", account_number="11223344")["match"] is False


def test_auth_and_validation(env):
    client, _, _ = env
    assert client.post("/v1/payee/check", json={"iban": "x"},
                       headers={"X-API-Key": "nope"}).status_code == 401
    assert client.post("/v1/payee/check", json={"iban": "GB00BAD"}).status_code == 422


def test_evidence_pack_has_no_raw_identifiers(env):
    client, fx, crawled = env
    cid = crawled["AD-1001"]["campaign_id"]
    pack = client.get(f"/v1/campaigns/{cid}/evidence-pack").json()
    assert pack["summary"] == {"ads_and_posts_seen": 2, "victim_reports": 1, "payment_details": 3}
    assert all(a["path_to_payment"] for a in pack["ads_and_posts"])
    raw = json.dumps(pack)
    k = fx["known"]
    for secret in (k["uk_a"][1], k["uk_b"][1], k["tron"]):
        assert secret not in raw
    html = client.get(f"/v1/campaigns/{cid}/evidence-pack?format=html").text
    assert "data:image/png;base64" in html and k["tron"] not in html


def test_social_submission_links_tiktok_screenshot_to_mule_campaign(env):
    """Screenshot-only TikTok post -> AI reads bank details -> joins the shop campaign."""
    import base64

    import scamtrace.api as api_mod
    from scamtrace import ai
    from test_ai import FakeClient, analysis

    client, fx, crawled = env
    k = fx["known"]
    fake = FakeClient(lambda kw: analysis(
        payment_instructions=[{"kind": "uk_account", "seen_in": "image",
                               "raw": f"Sort code {k['uk_c'][0]} Account {k['uk_c'][1]}"}],
        calls_to_action=[{"type": "whatsapp", "value": "07700 900456"}])
        if "screenshot" not in kw["messages"][0]["content"][-1]["text"] else analysis())
    old = api_mod.analyser
    api_mod.analyser = ai.Analyser(client=fake)
    try:
        png = (DEMO / "sites" / "_posts" / "tt_furniture.png").read_bytes()
        r = client.post("/v1/sightings/social", json={
            "submission_id": "SUB-T1", "handle": "garden.bargains.uk",
            "post_url": "https://www.tiktok.com/@garden.bargains.uk/video/1",
            "screenshots_b64": [base64.b64encode(png).decode()]}).json()
    finally:
        api_mod.analyser = old
    assert r["engine"].startswith("claude")
    assert any(p["type"] == "uk_account" for p in r["payment_details"])
    shop = client.post("/v1/payee/check", json={
        "sort_code": k["uk_c"][0], "account_number": k["uk_c"][1]}).json()
    assert "tiktok" in shop["campaign"]["platforms"]
    assert shop["campaign"]["id"] == r["campaign_id"]
    assert client.post("/v1/sightings/social", json={"submission_id": "x"}).status_code == 422


def test_database_holds_no_full_identifiers(env):
    """Privacy by design: no column of any table contains a full identifier."""
    import scamtrace.api as api_mod

    _, fx, _ = env
    k = fx["known"]
    secrets = [k["uk_a"][1], k["uk_b"][1], k["uk_c"][1], k["tron"], k["iban_c"]]
    db = api_mod.store.db
    dump = "\n".join(str(tuple(r)) for t in ("sightings", "identifiers")
                     for r in db.execute(f"SELECT * FROM {t}"))
    assert dump and not [s for s in secrets if s in dump]
