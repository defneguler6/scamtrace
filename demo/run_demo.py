"""End-to-end demo on synthetic scam sites and social posts.

  python demo/run_demo.py

1. Serves five synthetic websites locally (four scams, one legitimate shop).
2. Crawls each advert from landing page to payment step.
3. Social media: an Instagram ad and a TikTok ad (in the shape the official
   ad-library APIs return) and three submitted TikTok/Instagram posts with
   screenshots. The AI reads each post and the pages its links lead to.
4. Adds two victim reports.
5. Runs payee checks the way a payment firm would.
6. Writes evidence packs to demo/output/.

With ANTHROPIC_API_KEY set the AI layer uses Claude (and reads screenshots);
without it a keyword heuristic runs instead and images are not read.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import shutil
import sys
import threading
import base64
from pathlib import Path
from urllib.parse import urlsplit

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
    import scamtrace.api as api_mod
    from scamtrace.social import process
    from scamtrace.sources import meta_ad_library, tiktok_ccl

    servers = serve_sites(fx["ports"])
    api = TestClient(api_mod.app, headers={"X-API-Key": "demo-key"})
    engine = api_mod.analyser.engine
    print(f"AI layer: {'Claude (' + api_mod.analyser.model + ')' if engine == 'claude' else 'OFF (keyword heuristic, screenshots not read). Set ANTHROPIC_API_KEY to turn it on.'}")

    print("\n== 1. Crawling adverts ==")
    for ad in fx["ads"]:
        body = {k: v for k, v in ad.items() if k != "site"}
        body["landing_url"] = f"http://127.0.0.1:{fx['ports'][ad['site']]}/index.html"
        r = api.post("/v1/sightings/ad", json=body).json()
        found = ", ".join(f"{p['type']} {p['masked']}" for p in r["payment_details"]) or "none"
        print(f"{r['ad_id']}: {r['steps']} steps -> {r['payment_page'].split('/')[-1].split('?')[0]:<14}"
              f" payment details: {found}" + (f"  ERROR {r['error']}" if r["error"] else ""))

    print("\n== 2. Social media: TikTok and Instagram ==")
    soc = fx["social"]
    posts = ROOT / "sites" / "_posts"

    def local(url):
        host = urlsplit(url if "://" in url else "https://" + url).netloc
        site = soc["domain_map"].get(host)
        return f"http://127.0.0.1:{fx['ports'][site]}/index.html" if site else url

    def show(r):
        pay = ", ".join(f"{p['type']} {p['masked']}" for p in r["payment_details"]) or "none"
        con = ", ".join(p["masked"] for p in r["contacts"]) or "none"
        print(f"{r['sighting_id']:<28} {r['verdict']:<17} {r['scam_likelihood']:.2f} "
              f"{r['scam_type']:<11} -> {r['campaign_id']}\n"
              f"{'':<28} payment: {pay}\n{'':<28} accounts/contacts: {con}")
        if r.get("summary") and engine == "claude":
            print(f"{'':<28} AI: {r['summary']}")

    print("[Instagram ad from Meta Ad Library API record]")
    for rec in soc["meta_ads"]:
        item = meta_ad_library.parse(rec)
        item.landing_urls = [local(u) for u in item.landing_urls]
        show(process(item, api_mod.store, api_mod.EVIDENCE_DIR, api_mod.analyser))
    print("[TikTok ad from Commercial Content API record]")
    for rec in soc["tiktok_ads"]:
        item = tiktok_ccl.parse(rec, download_images=False)
        item.images = [(posts / "tt_hydrospa_ad.png").read_bytes()]
        item.landing_urls = [local(u) for u in item.landing_urls]
        show(process(item, api_mod.store, api_mod.EVIDENCE_DIR, api_mod.analyser))
    print("[Posts submitted with screenshots]")
    for sub in soc["submissions"]:
        body = {k: v for k, v in sub.items() if k != "screenshot"}
        body["screenshots_b64"] = [base64.b64encode(
            (posts / f"{sub['screenshot']}.png").read_bytes()).decode()]
        show(api.post("/v1/sightings/social", json=body).json())

    print("\n== 3. Victim reports ==")
    for rep in fx["reports"]:
        r = api.post("/v1/sightings/report", json=rep).json()
        print(f"{r['report_id']}: {', '.join(p['masked'] for p in r['payment_details'])}"
              f" -> campaign {r['campaign_id']}")

    print("\n== 4. Campaigns ==")
    campaigns = api.get("/v1/campaigns").json()
    for c in campaigns:
        plats = ",".join(c["platforms"]) or "-"
        print(f"{c['id']}  {c['scam_type']:<11} platforms={plats:<19} websites={c['websites']}"
              f"  payment details={c['payment_details']}")

    print("\n== 5. Payee checks ==")
    k = fx["known"]
    checks = [
        ("Customer about to pay the investment scam (site A account)",
         {"sort_code": k["uk_a"][0], "account_number": k["uk_a"][1], "direction": "outbound"}),
        ("Money arriving at a purchase-scam mule account",
         {"sort_code": k["uk_c"][0], "account_number": k["uk_c"][1], "direction": "inbound"}),
        ("USDT wallet from the investment kit",
         {"wallet": k["tron"], "direction": "outbound"}),
        ("USDT wallet from the Instagram job-scam post",
         {"wallet": k["tron_job"], "direction": "outbound"}),
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
                 f" platforms: {','.join(r['campaign']['platforms']) or '-'},"
                 f" {r['campaign']['websites']} sites, {r['campaign']['linked_payment_details']}"
                 f" linked payment details)\n    action: {r['recommended_action']}"
                 if r["match"] else ""))
    (OUT / "payee_checks.json").write_text(json.dumps(results, indent=2))

    print("\n== 6. Evidence packs ==")
    for c in campaigns:
        pack = api.get(f"/v1/campaigns/{c['id']}/evidence-pack").json()
        (OUT / f"evidence_{c['id']}.json").write_text(json.dumps(pack, indent=2))
        html = api.get(f"/v1/campaigns/{c['id']}/evidence-pack?format=html").text
        (OUT / f"evidence_{c['id']}.html").write_text(html)
        print(f"{OUT / ('evidence_' + c['id'] + '.html')}")

    if engine != "claude":
        print("\nNote: AI was off, so the bank details that appear only in the TikTok "
              "screenshot (SUB-T1) were not read and that post is not linked to the "
              "purchase-scam campaign. Set ANTHROPIC_API_KEY and run again.")
    for s in servers:
        s.shutdown()


if __name__ == "__main__":
    main()
