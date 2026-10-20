"""End-to-end demo on synthetic scam sites.

  python demo/run_demo.py

1. Serves five synthetic websites locally (four scams, one legitimate shop).
2. Crawls each advert from landing page to payment step.
3. Adds two victim reports.
4. Runs payee checks the way a payment firm would.
5. Writes evidence packs to demo/output/.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import shutil
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "output"
sys.path.insert(0, str(ROOT.parent))


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve_sites(ports: dict[str, int]):
    servers = []
    for name, port in ports.items():
        handler = functools.partial(_Quiet, directory=str(ROOT / "sites" / name))
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def main():
    import make_sites
    make_sites.main()
    fx = json.loads((ROOT / "fixtures.json").read_text())

    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir()
    os.environ["SCAMTRACE_DB"] = str(OUT / "demo.db")
    os.environ["SCAMTRACE_EVIDENCE"] = str(OUT / "screens")
    os.environ.setdefault("SCAMTRACE_HASH_KEY", "demo-hash-key")

    from fastapi.testclient import TestClient
    from scamtrace.api import app

    servers = serve_sites(fx["ports"])
    api = TestClient(app, headers={"X-API-Key": "demo-key"})

    print("\n== 1. Crawling adverts ==")
    for ad in fx["ads"]:
        body = {k: v for k, v in ad.items() if k != "site"}
        body["landing_url"] = f"http://127.0.0.1:{fx['ports'][ad['site']]}/index.html"
        r = api.post("/v1/sightings/ad", json=body).json()
        found = ", ".join(f"{p['type']} {p['masked']}" for p in r["payment_details"]) or "none"
        print(f"{r['ad_id']}: {r['steps']} steps -> {r['payment_page'].split('/')[-1].split('?')[0]:<14}"
              f" payment details: {found}" + (f"  ERROR {r['error']}" if r["error"] else ""))

    print("\n== 2. Victim reports ==")
    for rep in fx["reports"]:
        r = api.post("/v1/sightings/report", json=rep).json()
        print(f"{r['report_id']}: {', '.join(p['masked'] for p in r['payment_details'])}"
              f" -> campaign {r['campaign_id']}")

    print("\n== 3. Campaigns ==")
    campaigns = api.get("/v1/campaigns").json()
    for c in campaigns:
        print(f"{c['id']}  {c['scam_type']:<10} websites={c['websites']}"
              f"  payment details={c['payment_details']}")

    print("\n== 4. Payee checks ==")
    k = fx["known"]
    checks = [
        ("Customer about to pay the investment scam (site A account)",
         {"sort_code": k["uk_a"][0], "account_number": k["uk_a"][1], "direction": "outbound"}),
        ("Money arriving at a purchase-scam mule account",
         {"sort_code": k["uk_c"][0], "account_number": k["uk_c"][1], "direction": "inbound"}),
        ("USDT wallet from the investment kit",
         {"wallet": k["tron"], "direction": "outbound"}),
        ("Account known only from a victim report",
         {"sort_code": "00-33-44", "account_number": "12121212"}),
        ("Clean payee", {"sort_code": "00-77-88", "account_number": "11223344"}),
    ]
    results = []
    for label, q in checks:
        r = api.post("/v1/payee/check", json=q).json()
        results.append({"check": label, "request": q, "response": r})
        print(f"- {label}\n    risk={r['risk']}"
              + (f"  campaign={r['campaign']['id']} ({r['campaign']['scam_type']},"
                 f" {r['campaign']['websites']} sites, {r['campaign']['linked_payment_details']}"
                 f" linked payment details)\n    action: {r['recommended_action']}"
                 if r["match"] else ""))
    (OUT / "payee_checks.json").write_text(json.dumps(results, indent=2))

    print("\n== 5. Evidence packs ==")
    for c in campaigns:
        pack = api.get(f"/v1/campaigns/{c['id']}/evidence-pack").json()
        (OUT / f"evidence_{c['id']}.json").write_text(json.dumps(pack, indent=2))
        html = api.get(f"/v1/campaigns/{c['id']}/evidence-pack?format=html").text
        (OUT / f"evidence_{c['id']}.html").write_text(html)
        print(f"{OUT / ('evidence_' + c['id'] + '.html')}")

    for s in servers:
        s.shutdown()


if __name__ == "__main__":
    main()
