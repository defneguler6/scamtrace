"""Label a campaign as an investment or a purchase scam.

A transparent keyword scorer, so every label can be explained in an
evidence pack. It is the baseline the LLM classifier (roadmap) has to beat.
"""

from __future__ import annotations

import re

SIGNALS = {
    "investment": [
        r"\binvest", r"\breturns?\b", r"\bprofit", r"\btrading\b", r"\bcrypto",
        r"\bguarantee", r"\bdaily (?:income|profit|returns?)", r"\broi\b",
        r"\bdeposit\b", r"\bportfolio", r"\bwithdraw", r"\bbitcoin",
        r"\busdt\b", r"\bpassive income", r"\bplatform\b", r"\baccount manager",
    ],
    "job": [
        r"\bearn £?\d+\s*(?:a|per|/)\s*(?:day|hour)", r"\blike and review",
        r"\b(?:simple|easy|online) tasks?\b", r"\bno experience", r"\bhr team\b",
        r"\bwork from (?:your )?(?:phone|home)", r"\bstarter fee\b", r"\bactivate your account",
        r"\bcommission\b", r"\brecruit",
    ],
    "purchase": [
        r"\bbasket\b", r"\bcheckout\b", r"\bdelivery\b", r"\bclearance\b",
        r"\b\d{2}% off\b", r"\border\b", r"\bin stock\b", r"\bshipping\b",
        r"\bsale\b", r"\bbuy now\b", r"\bprice\b", r"\bwarehouse\b",
    ],
}

PRESSURE = [
    r"\blimited (?:time|spaces|places)", r"\bonly \d+ (?:left|places|spots)",
    r"\bbank transfer only\b", r"\bdo not tell (?:your )?bank",
    r"\bact now\b", r"\bexpires? (?:today|tonight|in)",
    r"\bif your bank asks\b", r"\bsay (?:it is|it's) (?:for )?(?:a )?(?:family|friend)",
]


def _count(patterns, text):
    hits = []
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            hits.append(m.group(0).lower())
    return hits


def classify(text: str) -> dict:
    scores = {k: _count(v, text) for k, v in SIGNALS.items()}
    label = max(scores, key=lambda k: len(scores[k]))
    if not scores[label]:
        label = "unknown"
    pressure = _count(PRESSURE, text)
    return {
        "scam_type": label,
        "signals": scores.get(label, []),
        "pressure_tactics": pressure,
    }
