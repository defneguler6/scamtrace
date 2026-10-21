"""Build a small SYNTHETIC labelled set so the evaluation script can be tried.

    python eval/make_sample.py      -> eval/sample.jsonl + eval/images/

It shows the format only. Fourteen invented posts cannot tell you which
model is better: build a real set (see README, "Choosing a model").
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "demo"))

import make_sites  # noqa: E402
from scamtrace import identifiers as ids  # noqa: E402

rng = random.Random(7)
BTC = ids.bech32_encode("bc", [0] + [rng.randrange(32) for _ in range(32)])
IBAN_RENT = ids.iban_with_check_digits("GB", "TEST00440155667788")

ITEMS = [
    # ---- scams
    {"id": "s1", "platform": "tiktok", "text": "", "images": ["images/tt_furniture.png"],
     "label": "scam", "scam_type": "purchase",
     "payment_details": [{"kind": "uk_account",
                          "value": f"{make_sites.UK_C[0]} {make_sites.UK_C[1]}"}],
     "notes": "payment details only in the image"},
    {"id": "s2", "platform": "tiktok", "text": "", "images": ["images/tt_hydrospa_ad.png"],
     "label": "scam", "scam_type": "purchase", "notes": "image-only ad, no payment details"},
    {"id": "s3", "platform": "instagram", "images": ["images/ig_jobs.png"],
     "text": "Earn £300/day from your phone! Just like and review products. Message our "
             f"HR team on Telegram @easytasks_uk_hr. 50 USDT starter fee (TRC20): "
             f"{make_sites.TRON_JOB}",
     "label": "scam", "scam_type": "job",
     "payment_details": [{"kind": "crypto_wallet", "value": make_sites.TRON_JOB}]},
    {"id": "s4", "platform": "instagram", "label": "scam", "scam_type": "investment",
     "text": "Britannia Money Daily: the AI trading app the banks don't want you to know "
             "about. Members earn daily returns of up to 4%, guaranteed. Spaces for UK "
             "residents close tonight."},
    {"id": "s5", "platform": "facebook", "label": "scam", "scam_type": "purchase",
     "text": "Can't go anymore 😢 2 standing tickets for Saturday's arena show, £80 each. "
             "Bank transfer only, no PayPal sorry. Sort code 00-21-43 account 66554433."
     , "payment_details": [{"kind": "uk_account", "value": "00-21-43 66554433"}]},
    {"id": "s6", "platform": "tiktok", "label": "scam", "scam_type": "giveaway",
     "text": "🚀 Celebrating 10M users! Send any amount of BTC to our event wallet and "
             f"receive DOUBLE back instantly: {BTC}. Ends in 30 minutes!",
     "payment_details": [{"kind": "crypto_wallet", "value": BTC}]},
    {"id": "s7", "platform": "facebook", "label": "scam", "scam_type": "rental",
     "text": "Lovely studio flat, Zone 1, £650 pcm all bills included. I'm working abroad "
             "so can't do viewings, but once you pay the first month and deposit to "
             f"{IBAN_RENT} I will post you the keys.",
     "payment_details": [{"kind": "iban", "value": IBAN_RENT}]},
    {"id": "s8", "platform": "instagram", "label": "scam", "scam_type": "loan",
     "text": "Guaranteed loans up to £10,000, bad credit OK, no checks! Pay the £99 "
             "admin fee to sort code 00-65-87 acc 19283746 and get your money today.",
     "payment_details": [{"kind": "uk_account", "value": "00-65-87 19283746"}]},
    {"id": "s9", "platform": "instagram", "label": "scam", "scam_type": "impersonation",
     "text": "BrightBank Support here 👋 We've noticed unusual activity and locked your "
             "account. DM us your details now so we can move your money to a safe account."},
    # ---- legitimate
    {"id": "l1", "platform": "instagram", "images": ["images/ig_bakery.png"],
     "label": "legitimate", "text": "Fresh sourdough every Saturday at the market, stall 12."},
    {"id": "l2", "platform": "instagram", "label": "legitimate",
     "text": "Our autumn sale is on: 20% off knitwear in store and online until Sunday. "
             "Free returns within 30 days."},
    {"id": "l3", "platform": "facebook", "label": "legitimate",
     "text": "We're hiring a junior developer in Manchester, £38,000, hybrid. Apply through "
             "the careers page on our website."},
    {"id": "l4", "platform": "facebook", "label": "legitimate",
     "text": "Selling my road bike, £250 ono. Collection only from Leeds, happy for you to "
             "test ride it first. Cash on collection."},
    {"id": "l5", "platform": "instagram", "label": "legitimate",
     "text": "Our easy access savings account now pays 4.1% AER variable. Eligible "
             "deposits protected by the FSCS. T&Cs apply."},
]


def main():
    make_sites.render_posts(HERE / "images")
    lines = ["# SYNTHETIC sample: format demo only. Build a real labelled set for decisions."]
    lines += [json.dumps(i, ensure_ascii=False) for i in ITEMS]
    (HERE / "sample.jsonl").write_text("\n".join(lines) + "\n")
    print(f"wrote {len(ITEMS)} labelled posts to {HERE / 'sample.jsonl'}")


if __name__ == "__main__":
    main()
