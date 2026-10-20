"""Find payment instructions in a scam page.

Input is the HTML (or plain text) of a page the crawler reached.
Output is a list of Findings: a validated identifier plus a short,
digit-masked context snippet for the evidence pack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

from . import identifiers as ids


@dataclass
class Finding:
    identifier: ids.Identifier
    snippet: str
    url: str = ""


# Labelled UK details: "Sort code: 12-34-56", "Account No. 12345678".
_SORT = re.compile(
    r"sort[\s-]*code\b[^0-9]{0,25}(\d{2}\s?[-–.\s]?\s?\d{2}\s?[-–.\s]?\s?\d{2})\b",
    re.I,
)
_ACC = re.compile(
    r"(?:acc(?:ount)?|a/c)\.?\s*(?:no|number|num|#)?\.?[^0-9]{0,25}(\d{7,8})\b",
    re.I,
)
# Unlabelled pair as people often paste it: "12-34-56 12345678".
_PAIR = re.compile(r"\b(\d{2}-\d{2}-\d{2})[\s,/|]+(\d{8})\b")

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){10,30}\b")
_ETH = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

_PAIR_WINDOW = 300  # characters between a sort code and its account number


def _mask_digits(s: str) -> str:
    # Keep the snippet readable for an analyst but never store full numbers.
    s = re.sub(r"\d(?=(?:[\s-]*\d){4})", "•", s)
    return re.sub(r"\s+", " ", s).strip()


def _snippet(text: str, start: int, end: int, pad: int = 70) -> str:
    return _mask_digits(text[max(0, start - pad): end + pad])


def page_text(html: str) -> tuple[str, list[str]]:
    """Visible text plus every value a payment detail could hide in."""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text("\n")
    extras: list[str] = []
    for tag in soup.find_all(True):
        for attr in ("href", "value", "data-copy", "data-clipboard-text",
                     "data-address", "title", "alt"):
            v = tag.get(attr)
            if isinstance(v, str) and v.strip():
                extras.append(v.strip())
    return text, extras


def _uk_accounts(text: str):
    used = set()
    sorts = [(m.start(), m.end(), m.group(1)) for m in _SORT.finditer(text)]
    accs = [(m.start(), m.end(), m.group(1)) for m in _ACC.finditer(text)]
    for s_start, s_end, sc in sorts:
        best = None
        for a in accs:
            if a in used:
                continue
            dist = min(abs(a[0] - s_end), abs(s_start - a[1]))
            if dist <= _PAIR_WINDOW and (best is None or dist < best[0]):
                best = (dist, a)
        if best:
            a = best[1]
            used.add(a)
            ident = ids.uk_account(sc, a[2])
            if ident:
                yield ident, _snippet(text, min(s_start, a[0]), max(s_end, a[1]))
    for m in _PAIR.finditer(text):
        ident = ids.uk_account(m.group(1), m.group(2))
        if ident:
            yield ident, _snippet(text, m.start(), m.end())


def extract(html: str, url: str = "") -> list[Finding]:
    text, extras = page_text(html)
    blob = text + "\n" + "\n".join(extras)
    found: dict[str, Finding] = {}
    raws: dict[str, str] = {}  # raw text -> masked, to scrub every snippet

    def add(ident, snip, raw=None):
        if ident and raw:
            raws[raw] = ident.masked
        if ident and ident.token not in found:
            found[ident.token] = Finding(ident, snip, url)

    for ident, snip in _uk_accounts(text):
        add(ident, snip)

    for m in _IBAN.finditer(blob.upper()):
        add(ids.iban(m.group(0)), _snippet(blob, m.start(), m.end()), m.group(0))

    for rx, fn in ((_ETH, ids.eth), (_TRON, ids.tron), (_BTC, ids.btc)):
        for m in rx.finditer(blob):
            add(fn(m.group(0)), _snippet(blob, m.start(), m.end()), m.group(0))

    for m in _URL.finditer(blob):
        add(ids.payment_link(m.group(0)), _snippet(blob, m.start(), m.end()), m.group(0))
    for e in extras:
        if e.lower().startswith(("http", "paypal.me", "monzo.me", "revolut.me")):
            add(ids.payment_link(e), _mask_digits(e), e)

    # A snippet can contain a neighbouring wallet or link: mask those too.
    for f in found.values():
        for raw, masked in sorted(raws.items(), key=lambda kv: -len(kv[0])):
            f.snippet = f.snippet.replace(raw, masked)
    return list(found.values())
