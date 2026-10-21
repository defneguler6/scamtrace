"""Generate SYNTHETIC scam websites for the demo and tests.

Nothing here is real: sort codes start with 00 (not issued to banks),
IBANs use the bank code TEST, wallets are random keys made with valid
checksums, and brand names are invented.

  python demo/make_sites.py   -> writes demo/sites/<site>/ and demo/fixtures.json
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT.parent))
from scamtrace import identifiers as ids  # noqa: E402

rng = random.Random(2026)

UK_A = ("00-12-34", "31926819")   # investment kit, site A
UK_B = ("00-56-78", "55501234")   # investment kit, site B
UK_C = ("00-90-12", "40404017")   # purchase scams, both shops
IBAN_C = ids.iban_with_check_digits("GB", "TEST00901240404017")
TRON = ids.b58encode_check(b"\x41" + bytes(rng.randrange(256) for _ in range(20)))
PORTS = {"yield_a": 8701, "yield_b": 8702, "shop_a": 8703, "shop_b": 8704, "legit": 8705}

CSS = """<style>body{font:16px/1.5 system-ui;margin:0;padding:20px;max-width:440px}
.btn{display:inline-block;background:#0a7;color:#fff;padding:12px 18px;border-radius:6px;
text-decoration:none;border:0;font-size:16px}.box{border:1px solid #ccc;padding:12px;
border-radius:6px;margin:12px 0}small{color:#777}input{display:block;margin:6px 0;
padding:8px;width:90%}</style>"""


def page(title, body):
    return (f"<!doctype html><html><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width'><title>{title}</title>"
            f"{CSS}</head><body>{body}</body></html>")


def investment_kit(brand: str, uk: tuple[str, str]) -> dict[str, str]:
    """One scam 'kit' re-skinned under different brands."""
    footer = ("<small>Trading involves risk. Results shown are from selected "
              "members. Registered office available on request.</small>")
    return {
        "index.html": page(brand, f"""
<h1>{brand}: the AI trading platform everyone is talking about</h1>
<p>Our AI trading engine finds profitable crypto trades while you sleep.
Members report daily returns of up to 4% with guaranteed capital protection.</p>
<p>Limited spaces for UK residents this week. Your personal account manager
will call you within 24 hours.</p>
<a class=btn href="register.html">Start earning now</a>
<div class=box>“I made £3,200 in my first month.” – Sarah, Leeds</div>{footer}"""),
        "register.html": page(brand, f"""
<h2>Open your {brand} account</h2>
<form action="deposit.html" method="get">
<input name="first_name" placeholder="First name" required>
<input name="last_name" placeholder="Last name" required>
<input name="email" type="email" placeholder="Email" required>
<input name="phone" type="tel" placeholder="Mobile" required>
<label><input type="checkbox" name="agree" required> I accept the terms</label>
<button class=btn type="submit">Create account</button></form>{footer}"""),
        "deposit.html": page(brand, f"""
<h2>Fund your account</h2>
<p>Minimum deposit £250. Your portfolio starts trading as soon as funds arrive.</p>
<button class=btn id=show>Show deposit details</button>
<div id=details></div>
<script>
document.getElementById('show').onclick = function () {{
  document.getElementById('details').innerHTML =
   '<div class=box><b>Bank transfer</b><br>Account name: GLOBAL ASSET SERVICES<br>' +
   'Sort code: {uk[0]}<br>Account number: {uk[1]}<br>Reference: your mobile number</div>' +
   '<div class=box><b>USDT (TRC20)</b><br><code>{TRON}</code></div>' +
   '<p>If your bank asks, say it is a payment to a friend. Banks block crypto ' +
   'gains to protect their own profits.</p>';
}};
</script>{footer}"""),
    }


def shop_a() -> dict[str, str]:
    brand = "Oakline Garden Clearance"
    return {
        "index.html": page(brand, f"""
<h1>{brand}</h1><p>Warehouse closing down: 70% off all rattan garden sets.
Free UK delivery. Only 6 left in stock.</p>
<div class=box><b>8-seat corner sofa set</b><br><s>£1,299</s> £389
<br><a class=btn href="product.html">View offer</a></div>"""),
        "product.html": page(brand, """
<h2>8-seat rattan corner sofa set</h2><p>Price £389 including delivery.
Sale ends tonight.</p><a class=btn href="checkout.html">Buy now</a>"""),
        "checkout.html": page(brand, f"""
<h2>Checkout</h2><p>Order total: £389</p>
<p><b>Bank transfer only</b> – card payments are temporarily unavailable.
Pay by transfer for an extra 20% off.</p>
<div class=box>Payee: Oakline Trading<br>Sort code {UK_C[0]}<br>
Account no. {UK_C[1]}<br>International: {IBAN_C}</div>
<p>Your order ships within 2 working days of payment.</p>"""),
    }


def shop_b() -> dict[str, str]:
    brand = "Hydro Spa Outlet"
    return {
        "index.html": page(brand, f"""
<h1>{brand}</h1><p>Ex-display hot tubs from £499. Customs overstock must go.</p>
<a class=btn href="order.html">Order now</a>"""),
        "order.html": page(brand, f"""
<h2>Complete your order</h2><p>To secure the reduced price please pay by
bank transfer within 2 hours.</p>
<p>Payee details: {UK_C[0]} {UK_C[1]} (H Spa Ltd)</p>"""),
    }


def legit() -> dict[str, str]:
    brand = "Willow &amp; Field Furniture"
    return {
        "index.html": page(brand, f"""
<h1>{brand}</h1><p>Handmade garden furniture. 2-year guarantee.</p>
<a class=btn href="checkout.html">Buy now</a>
<small>Willow and Field Ltd, company number 09876543. VAT GB 123 4567 89.
Call 0117 496 0123.</small>"""),
        "checkout.html": page(brand, """
<h2>Secure checkout</h2><form><input name=card placeholder="Card number">
<input name=expiry placeholder="MM/YY"><input name=cvc placeholder="CVC">
<button class=btn type=button>Pay securely</button></form>
<p>Order reference 20261020. Questions? Call 0117 496 0123.</p>"""),
    }


SITES = {
    "yield_a": investment_kit("QuantumYield AI", UK_A),
    "yield_b": investment_kit("NovaYield AI", UK_B),
    "shop_a": shop_a(),
    "shop_b": shop_b(),
    "legit": legit(),
}

ADS = [
    {"ad_id": "AD-1001", "platform": "Social platform A", "site": "yield_a",
     "ad_text": "Brits are quitting their jobs thanks to this AI trading app. "
                "Daily profits, guaranteed. Limited UK spaces!"},
    {"ad_id": "AD-1002", "platform": "Social platform B", "site": "yield_b",
     "ad_text": "Turn £250 into a monthly income with AI crypto trading. "
                "Spaces close tonight."},
    {"ad_id": "AD-2001", "platform": "Social platform A", "site": "shop_a",
     "ad_text": "Warehouse closing down! Rattan garden sets 70% off, free delivery."},
    {"ad_id": "AD-2002", "platform": "Social platform A", "site": "shop_b",
     "ad_text": "Ex-display hot tubs from £499 – customs overstock must go!"},
    {"ad_id": "AD-3001", "platform": "Social platform B", "site": "legit",
     "ad_text": "Handmade garden furniture with a 2-year guarantee."},
]

REPORTS = [
    {"report_id": "VR-501",
     "text": "I saw an AI trading advert. The account manager kept calling and "
             f"told me to send £2,000 to sort code {UK_B[0].replace('-', ' ')} "
             f"acc {UK_B[1]} and to say it was for a friend."},
    {"report_id": "VR-502",
     "text": "Bought a puppy on a marketplace, paid sort code 00-33-44 account "
             "number 12121212, never heard back."},
]


# ------------------------------------------------------- social media
# Fictional accounts and brands. Post "screenshots" are rendered from a
# generic card layout, not from any real app's interface.

TRON_JOB = ids.b58encode_check(b"\x41" + bytes(rng.randrange(256) for _ in range(20)))

# Shaped like a record from Meta's Ad Library API (ads_archive).
META_ADS = [{
    "id": "90001",
    "page_name": "QuantumYield Official",
    "publisher_platforms": ["INSTAGRAM", "FACEBOOK"],
    "ad_delivery_start_time": "2026-10-14",
    "ad_snapshot_url": "https://www.facebook.com/ads/archive/render_ad/?id=90001",
    "ad_creative_bodies": [
        "Britannia Money Daily: the AI trading app the banks don't want you to "
        "know about. Members earn daily returns of up to 4%, guaranteed. "
        "Spaces for UK residents close tonight."],
    "ad_creative_link_titles": ["Start earning with AI today"],
    "ad_creative_link_captions": ["quantumyield-ai.example"],
}]

# Shaped like a record from TikTok's Commercial Content API.
TIKTOK_ADS = [{
    "ad": {"id": "70001", "first_shown_date": "20261012", "status": "active",
           "image_urls": [], "videos": [],
           "landing_page_url": "hydrospa-outlet.example"},
    "advertiser": {"business_name": "HydroSpa Outlet UK"},
}]

# Where the fictional domains live in the demo.
DOMAIN_MAP = {
    "quantumyield-ai.example": "yield_a",
    "hydrospa-outlet.example": "shop_b",
}

POSTS = {
    # Organic TikTok post: payment details only in the screenshot.
    "tt_furniture": {
        "handle": "garden.bargains.uk", "platform": "TikTok",
        "lines": ["Clearing my late nan's garden furniture 🌿",
                  "8-seat rattan corner set, barely used. £150, can deliver.",
                  "Loads of interest so first to pay the deposit gets it!",
                  "WhatsApp me: 07700 900456",
                  "Deposit to: O TRADING",
                  f"Sort code {UK_C[0]}   Account {UK_C[1]}"],
    },
    # TikTok ad creative: the ad library gave no text, only this image.
    "tt_hydrospa_ad": {
        "handle": "HydroSpa Outlet UK", "platform": "Sponsored",
        "lines": ["EX-DISPLAY HOT TUBS FROM £499", "Customs overstock must go",
                  "Only this week · Free delivery", "Tap Shop now ↓"],
    },
    # Instagram job scam: everything in the caption text.
    "ig_jobs": {
        "handle": "easytasks.uk.hr", "platform": "Instagram",
        "lines": ["📲 Earn £300 a day from your phone!", "Just like and review products.",
                  "No experience needed. Limited places."],
    },
    "ig_bakery": {
        "handle": "rye.and.crumb", "platform": "Instagram",
        "lines": ["Fresh sourdough every Saturday 🍞", "Find us at the market, stall 12.",
                  "Pre-orders open on our website."],
    },
}

SUBMISSIONS = [
    {"submission_id": "SUB-T1", "post_url": "https://www.tiktok.com/@garden.bargains.uk/video/7400000000000000001",
     "handle": "garden.bargains.uk", "text": "", "screenshot": "tt_furniture"},
    {"submission_id": "SUB-I1", "post_url": "https://www.instagram.com/p/DEMO_JOBS1/",
     "handle": "easytasks.uk.hr", "screenshot": "ig_jobs",
     "text": "📲 Earn £300/day from your phone! Just like and review products, no "
             "experience needed. Limited places. Message our HR team on Telegram "
             f"@easytasks_uk_hr. Activate your account with a 50 USDT starter fee "
             f"(TRC20): {TRON_JOB}"},
    {"submission_id": "SUB-I2", "post_url": "https://www.instagram.com/p/DEMO_BAKERY/",
     "handle": "rye.and.crumb", "screenshot": "ig_bakery",
     "text": "Fresh sourdough every Saturday at the market, stall 12. Pre-orders on our website."},
]

POST_HTML = """<!doctype html><html><head><meta charset=utf-8><style>
body{{margin:0;font:17px/1.45 system-ui,sans-serif;background:#111;color:#fff;width:390px}}
.top{{display:flex;align-items:center;gap:10px;padding:14px}}
.av{{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#f6a,#7af)}}
.h{{font-weight:600}} .p{{font-size:12px;color:#aaa}}
.img{{height:230px;background:linear-gradient(160deg,#2d4,#174);display:flex;
align-items:center;justify-content:center;font-size:58px}}
.c{{padding:14px 16px 22px}} .c div{{margin:3px 0}}
</style></head><body><div class=top><div class=av></div><div><div class=h>@{handle}</div>
<div class=p>{platform} · demo post</div></div></div><div class=img>{emoji}</div>
<div class=c>{lines}</div></body></html>"""


def render_posts(out: Path):
    from playwright.sync_api import sync_playwright
    out.mkdir(parents=True, exist_ok=True)
    emoji = {"tt_furniture": "🪑", "tt_hydrospa_ad": "🛁", "ig_jobs": "💸", "ig_bakery": "🥖"}
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 390, "height": 600}, device_scale_factor=2)
        for key, post in POSTS.items():
            pg.set_content(POST_HTML.format(
                handle=post["handle"], platform=post["platform"], emoji=emoji[key],
                lines="".join(f"<div>{l}</div>" for l in post["lines"])))
            pg.screenshot(path=str(out / f"{key}.png"), full_page=True)
        b.close()


def main():
    for name, files in SITES.items():
        d = ROOT / "sites" / name
        d.mkdir(parents=True, exist_ok=True)
        for fname, html in files.items():
            (d / fname).write_text(html)
    fixtures = {
        "ports": PORTS,
        "ads": ADS,
        "reports": REPORTS,
        "known": {"uk_a": UK_A, "uk_b": UK_B, "uk_c": UK_C,
                  "iban_c": IBAN_C, "tron": TRON, "tron_job": TRON_JOB},
        "social": {"meta_ads": META_ADS, "tiktok_ads": TIKTOK_ADS,
                   "domain_map": DOMAIN_MAP, "submissions": SUBMISSIONS},
    }
    render_posts(ROOT / "sites" / "_posts")
    (ROOT / "fixtures.json").write_text(json.dumps(fixtures, indent=2))
    print(f"wrote {len(SITES)} synthetic sites to {ROOT / 'sites'}")


if __name__ == "__main__":
    main()
