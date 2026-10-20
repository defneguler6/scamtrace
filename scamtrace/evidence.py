"""Evidence pack: everything a fraud or claims team needs about one campaign.

The JSON form is for systems; the HTML form (screenshots embedded) is for
an analyst handling a reimbursement claim or a mule-account review.
"""

from __future__ import annotations

import base64
import html
from datetime import datetime, timezone
from pathlib import Path

KIND_LABEL = {
    "uk_account": "UK bank account", "iban": "IBAN", "btc": "Bitcoin wallet",
    "eth": "Ethereum wallet", "tron": "TRON (USDT) wallet",
    "payment_link": "Payment link",
}


def build(c: dict) -> dict:
    ads = [s for s in c["sightings"] if s["source"] == "ad_crawl"]
    reports = [s for s in c["sightings"] if s["source"] != "ad_crawl"]
    return {
        "campaign_id": c["campaign_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scam_type": c["scam_type"],
        "first_seen": c["first_seen"],
        "last_seen": c["last_seen"],
        "sites": c["sites"],
        "summary": {
            "ads_seen": len(ads),
            "victim_reports": len(reports),
            "payment_details": len(c["identifiers"]),
        },
        "payment_details": [{
            "type": KIND_LABEL.get(i["kind"], i["kind"]),
            "masked": i["masked"],
            "first_seen": i["first_seen"],
            "last_seen": i["last_seen"],
            "times_seen": i["sightings"],
            "context": i["snippet"],
            "page": i["url"],
        } for i in c["identifiers"]],
        "ads": [{
            "ad_id": s["id"],
            "platform": s["platform"],
            "ad_text": s["ad_text"],
            "seen_at": s["seen_at"],
            "landing_url": s["landing_url"],
            "payment_page": s["final_url"],
            "scam_signals": s["signals"],
            "pressure_tactics": s["pressure"],
            "path_to_payment": s["steps"],
        } for s in ads],
        "victim_reports": [{"report_id": s["id"], "received_at": s["seen_at"]}
                           for s in reports],
        "method_note": (
            "Payment details were captured by an automated browser following "
            "each advert to its payment step. Forms were filled only with a "
            "synthetic decoy profile; no payment was made. Identifiers are "
            "stored as keyed hashes and shown masked."
        ),
    }


def _img(evidence_dir: Path, name: str) -> str:
    p = evidence_dir / name
    if not p.exists():
        return ""
    b64 = base64.b64encode(p.read_bytes()).decode()
    return f'<img src="data:image/png;base64,{b64}" alt="{html.escape(name)}">'


def render_html(pack: dict, evidence_dir: Path) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(p['type'])}</td><td class=mono>{e(p['masked'])}</td>"
        f"<td>{e(p['first_seen'])}</td><td>{p['times_seen']}</td>"
        f"<td class=ctx>{e(p['context'] or '')}</td></tr>"
        for p in pack["payment_details"])
    ads = ""
    for a in pack["ads"]:
        steps = "".join(
            f"<li><b>{e(s['action'])}</b> → <span class=mono>{e(s['url'])}</span>"
            f" <small>{e(s['at'])} · sha256 {e(s['html_sha256'][:12])}…"
            f"{' · ' + str(s['findings']) + ' payment detail(s) found' if s['findings'] else ''}"
            f"</small><div class=shot>{_img(evidence_dir, s['screenshot'])}</div></li>"
            for s in a["path_to_payment"])
        tactics = ", ".join(a["pressure_tactics"]) or "none detected"
        ads += (
            f"<section class=ad><h3>Ad {e(a['ad_id'])} · {e(a['platform'] or '')}</h3>"
            f"<p class=adtext>“{e(a['ad_text'] or '')}”</p>"
            f"<p><b>Signals:</b> {e(', '.join(a['scam_signals']))}<br>"
            f"<b>Pressure tactics:</b> {e(tactics)}</p><ol>{steps}</ol></section>")
    s = pack["summary"]
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Evidence pack {e(pack['campaign_id'])}</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1d2433}}
h1{{font-size:22px;margin-bottom:4px}} .muted{{color:#5b6475}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.kpi{{border:1px solid #d8dde6;border-radius:8px;padding:10px 14px;min-width:120px}}
.kpi b{{display:block;font-size:22px}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{border-bottom:1px solid #e3e7ee;padding:6px 8px;text-align:left;vertical-align:top}}
.mono{{font-family:ui-monospace,monospace}} .ctx{{color:#5b6475;font-size:13px}}
.ad{{border:1px solid #d8dde6;border-radius:8px;padding:12px 16px;margin:16px 0}}
.adtext{{font-style:italic}} .shot img{{max-width:220px;border:1px solid #d8dde6;margin:6px 0}}
.note{{background:#f4f6fa;padding:10px 14px;border-radius:8px;font-size:13px}}
</style></head><body>
<h1>Scam campaign evidence pack · {e(pack['campaign_id'])}</h1>
<div class=muted>Type: {e(pack['scam_type'])} · first seen {e(pack['first_seen'])} ·
last seen {e(pack['last_seen'])} · generated {e(pack['generated_at'])}</div>
<div class=kpis><div class=kpi><b>{s['ads_seen']}</b>adverts</div>
<div class=kpi><b>{len(pack['sites'])}</b>websites</div>
<div class=kpi><b>{s['payment_details']}</b>payment details</div>
<div class=kpi><b>{s['victim_reports']}</b>victim reports</div></div>
<h2>Payment details used by this campaign</h2>
<table><tr><th>Type</th><th>Identifier</th><th>First seen</th><th>Times seen</th><th>Context</th></tr>{rows}</table>
<h2>Adverts and path to payment</h2>{ads}
<p class=note>{e(pack['method_note'])}</p></body></html>"""
