"""Evidence pack: everything a fraud or claims team needs about one campaign.

The JSON form is for systems; the HTML form (screenshots embedded) is for
an analyst handling a reimbursement claim or a mule-account review.
"""

from __future__ import annotations

import base64
import html
from datetime import datetime, timezone
from pathlib import Path

from .identifiers import PAYMENT_KINDS
from .store import ADVERT_SOURCES

KIND_LABEL = {
    "uk_account": "UK bank account", "iban": "IBAN", "btc": "Bitcoin wallet",
    "eth": "Ethereum wallet", "tron": "TRON (USDT) wallet",
    "payment_link": "Payment link", "phone": "WhatsApp / phone",
    "telegram": "Telegram", "social_handle": "Social media account",
}
PLATFORM_LABEL = {"tiktok": "TikTok", "instagram": "Instagram", "facebook": "Facebook"}


def _ai_view(a: dict | None) -> dict | None:
    if not a:
        return None
    return {
        "engine": a.get("engine"),
        "verdict": a.get("verdict"),
        "scam_likelihood": a.get("scam_likelihood"),
        "scam_type": a.get("scam_type"),
        "impersonates": a.get("impersonates"),
        "summary": a.get("summary"),
        "red_flags": a.get("red_flags", []),
        "calls_to_action": [c for c in a.get("calls_to_action", [])
                            if c.get("type") in ("link", "dm", "comment", "email", "other")],
        "unverified_payment_details": a.get("unverified_payment_details", []),
    }


def build(c: dict) -> dict:
    adverts = [s for s in c["sightings"] if s["source"] in ADVERT_SOURCES]
    reports = [s for s in c["sightings"] if s["source"] not in ADVERT_SOURCES]
    detail = lambda i: {
        "type": KIND_LABEL.get(i["kind"], i["kind"]),
        "masked": i["masked"],
        "first_seen": i["first_seen"],
        "last_seen": i["last_seen"],
        "times_seen": i["sightings"],
        "context": i["snippet"],
        "page": i["url"],
    }
    return {
        "campaign_id": c["campaign_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scam_type": c["scam_type"],
        "first_seen": c["first_seen"],
        "last_seen": c["last_seen"],
        "platforms": c["platforms"],
        "sites": c["sites"],
        "summary": {
            "ads_and_posts_seen": len(adverts),
            "victim_reports": len(reports),
            "payment_details": len(c["payment_identifiers"]),
        },
        "payment_details": [detail(i) for i in c["identifiers"] if i["kind"] in PAYMENT_KINDS],
        "linked_accounts_and_contacts": [detail(i) for i in c["identifiers"]
                                         if i["kind"] not in PAYMENT_KINDS],
        "ads_and_posts": [{
            "id": s["id"],
            "source": s["source"],
            "platform": s["platform"],
            "account": s["handle"],
            "post_url": s["post_url"],
            "text": s["ad_text"],
            "seen_at": s["seen_at"],
            "landing_url": s["landing_url"],
            "payment_page": s["final_url"],
            "keyword_signals": s["signals"],
            "pressure_tactics": s["pressure"],
            "ai_analysis": _ai_view(s["ai"]),
            "landing_page_ai": [_ai_view(p) for p in (s["ai"] or {}).get("landing_pages", [])]
                               if s["source"] == "social" else [],
            "screenshots_of_post": s["media"],
            "path_to_payment": s["steps"],
        } for s in adverts],
        "victim_reports": [{"report_id": s["id"], "received_at": s["seen_at"]}
                           for s in reports],
        "method_note": (
            "Posts and adverts come from official ad libraries or from "
            "submissions; ScamTrace does not scrape social platforms. An "
            "automated browser followed off-platform links to the payment "
            "step, filling forms only with a synthetic decoy profile and never "
            "paying. AI analysis is advisory: every account number or wallet "
            "it reports is re-checked by deterministic validators before it is "
            "stored. The database holds identifiers only as keyed hashes and "
            "masked forms; screenshots show each page exactly as captured and "
            "are kept as separate evidence files."
        ),
    }


def _img(evidence_dir: Path, name: str, cls: str = "") -> str:
    p = evidence_dir / name
    if not p.exists():
        return ""
    b64 = base64.b64encode(p.read_bytes()).decode()
    mime = "image/jpeg" if p.read_bytes()[:3] == b"\xff\xd8\xff" else "image/png"
    return f'<img class="{cls}" src="data:{mime};base64,{b64}" alt="{html.escape(name)}">'


def _ai_html(a: dict | None, title: str) -> str:
    if not a:
        return ""
    e = html.escape
    flags = "".join(f"<li><b>{e(f.get('flag', ''))}</b>: “{e(f.get('evidence', ''))}”</li>"
                    for f in a["red_flags"])
    unv = "".join(f"<li>{e(str(u.get('kind')))}: {e(str(u.get('as_read')))} "
                  f"(failed validation, not stored)</li>"
                  for u in a["unverified_payment_details"])
    pct = int(round(100 * float(a.get("scam_likelihood") or 0)))
    imp = f" · impersonates <b>{e(a['impersonates'])}</b>" if a.get("impersonates") else ""
    return (f"<div class=ai><div class=aihead>{e(title)} · <span class=pill>"
            f"{e(str(a.get('verdict')))} {pct}%</span> · {e(str(a.get('scam_type')))}{imp}"
            f" <small>({e(str(a.get('engine')))})</small></div>"
            f"<p>{e(a.get('summary') or '')}</p>"
            + (f"<ul>{flags}</ul>" if flags else "")
            + (f"<p class=muted>Unverified:</p><ul>{unv}</ul>" if unv else "") + "</div>")


def _rows(items) -> str:
    e = html.escape
    return "".join(
        f"<tr><td>{e(p['type'])}</td><td class=mono>{e(p['masked'])}</td>"
        f"<td>{e(p['first_seen'])}</td><td>{p['times_seen']}</td>"
        f"<td class=ctx>{e(p['context'] or '')}</td></tr>" for p in items)


def render_html(pack: dict, evidence_dir: Path) -> str:
    e = html.escape
    head = "<tr><th>Type</th><th>Identifier</th><th>First seen</th><th>Times seen</th><th>Context</th></tr>"
    linked = (f"<h2>Linked social accounts and contact channels</h2><table>{head}"
              f"{_rows(pack['linked_accounts_and_contacts'])}</table>"
              if pack["linked_accounts_and_contacts"] else "")
    items = ""
    for a in pack["ads_and_posts"]:
        steps = "".join(
            f"<li><b>{e(s['action'])}</b> → <span class=mono>{e(s['url'])}</span>"
            f" <small>{e(s['at'])} · sha256 {e(s['html_sha256'][:12])}…"
            f"{' · ' + str(s['findings']) + ' payment detail(s) found' if s['findings'] else ''}"
            f"</small><div class=shot>{_img(evidence_dir, s['screenshot'])}</div></li>"
            for s in a["path_to_payment"])
        posts = "".join(_img(evidence_dir, m, "post") for m in a["screenshots_of_post"])
        tactics = ", ".join(a["pressure_tactics"]) or "none detected"
        where = PLATFORM_LABEL.get(a["platform"] or "", a["platform"] or "")
        who = f" · @{e(a['account'])}" if a["account"] else ""
        link = (f"<p class=mono><small>{e(a['post_url'])}</small></p>" if a["post_url"] else "")
        kind = "Post" if a["source"] == "social" else "Advert"
        pages = "".join(_ai_html(p, "AI on payment page") for p in a["landing_page_ai"])
        items += (
            f"<section class=ad><h3>{kind} {e(a['id'])} · {e(where)}{who}</h3>{link}"
            f"<p class=adtext>“{e(a['text'] or '')}”</p>"
            f"{'<div class=posts>' + posts + '</div>' if posts else ''}"
            f"{_ai_html(a['ai_analysis'], 'AI on post') if a['source'] == 'social' else _ai_html(a['ai_analysis'], 'AI on payment page')}"
            f"<p><b>Keyword signals:</b> {e(', '.join(a['keyword_signals']) or 'none')}<br>"
            f"<b>Pressure tactics:</b> {e(tactics)}</p>{pages}"
            f"{'<h4>Path to payment</h4><ol>' + steps + '</ol>' if steps else ''}</section>")
    s = pack["summary"]
    plats = ", ".join(PLATFORM_LABEL.get(p, p) for p in pack["platforms"]) or "–"
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
.posts img{{max-width:260px;border:1px solid #d8dde6;border-radius:6px;margin:4px 8px 4px 0}}
.ai{{background:#f3f6fc;border-left:3px solid #3b5bdb;padding:8px 12px;margin:10px 0;border-radius:4px}}
.ai ul{{margin:4px 0}} .pill{{background:#3b5bdb;color:#fff;border-radius:10px;padding:1px 8px;font-size:13px}}
.note{{background:#f4f6fa;padding:10px 14px;border-radius:8px;font-size:13px}}
@media print{{body{{margin:0;max-width:none;font-size:11px}} .kpi,tr,.ai{{break-inside:avoid}}
h3{{break-after:avoid}} .ad{{padding:8px 12px;margin:10px 0}}
.ad ol{{display:flex;flex-wrap:wrap;gap:8px;padding:0;list-style:none;counter-reset:s}}
.ad ol li{{width:31%;break-inside:avoid;counter-increment:s;font-size:9.5px;word-break:break-all}}
.ad ol li::before{{content:"Step " counter(s) ": ";font-weight:600}}
.shot img{{max-width:100%;max-height:300px;object-fit:cover;object-position:top}}
.posts img{{max-width:170px;max-height:300px;object-fit:cover;object-position:top}}
*{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
@page{{size:A4;margin:14mm 12mm}}
</style></head><body>
<h1>Scam campaign evidence pack · {e(pack['campaign_id'])}</h1>
<div class=muted>Type: {e(pack['scam_type'])} · platforms: {e(plats)} · first seen {e(pack['first_seen'])} ·
last seen {e(pack['last_seen'])} · generated {e(pack['generated_at'])}</div>
<div class=kpis><div class=kpi><b>{s['ads_and_posts_seen']}</b>ads &amp; posts</div>
<div class=kpi><b>{len(pack['sites'])}</b>websites</div>
<div class=kpi><b>{s['payment_details']}</b>payment details</div>
<div class=kpi><b>{s['victim_reports']}</b>victim reports</div></div>
<h2>Payment details used by this campaign</h2>
<table>{head}{_rows(pack['payment_details'])}</table>{linked}
<h2>Ads, posts and path to payment</h2>{items}
<p class=note>{e(pack['method_note'])}</p></body></html>"""


def html_to_pdf(html_text: str, path: Path) -> Path:
    """Render an evidence pack to an A4 PDF with the headless browser."""
    from playwright.sync_api import sync_playwright
    path = Path(path)
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.set_content(html_text, wait_until="load")
        page.pdf(path=str(path), format="A4", print_background=True,
                 prefer_css_page_size=True)
        b.close()
    return path
