"""Group crawled ads into scam campaigns.

Two sightings belong to the same campaign when they share
  * a payment identifier (same mule account or wallet), or
  * a site (same registrable domain), or
  * a page template (near-identical text, i.e. one kit on many domains).
Campaigns are the connected components of that graph.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

TEXT_SIMILARITY = 0.55  # Jaccard over 5-word shingles


def site_key(url: str) -> str:
    host = urlsplit(url).netloc.lower()
    if not host:
        return ""
    name, _, port = host.partition(":")
    if name in ("localhost", "127.0.0.1"):
        return host  # demo sites: one "domain" per port
    labels = name.split(".")
    keep = 3 if len(labels) >= 3 and labels[-2] in ("co", "org", "gov", "ac") else 2
    return ".".join(labels[-keep:])


def shingles(text: str, k: int = 5) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {" ".join(words[i:i + k]) for i in range(max(0, len(words) - k + 1))}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class _UF:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def campaigns(sightings: list[dict]) -> dict[str, list[str]]:
    """sightings: [{id, tokens:set, urls:[...], text:str}] -> {campaign_id: [ids]}.

    Returns the reasons each pair was linked as well, for the evidence pack.
    """
    uf = _UF()
    by_token: dict[str, str] = {}
    by_site: dict[str, str] = {}
    sh = {}
    for s in sightings:
        uf.find(s["id"])
        for t in s["tokens"]:
            if t in by_token:
                uf.union(s["id"], by_token[t])
            else:
                by_token[t] = s["id"]
        for u in s.get("urls", []):
            k = site_key(u)
            if not k:
                continue
            if k in by_site:
                uf.union(s["id"], by_site[k])
            else:
                by_site[k] = s["id"]
        if s.get("text"):
            sh[s["id"]] = shingles(s["text"])
    ids_ = list(sh)
    for i, a in enumerate(ids_):
        for b in ids_[i + 1:]:
            if jaccard(sh[a], sh[b]) >= TEXT_SIMILARITY:
                uf.union(a, b)

    groups: dict[str, list[str]] = {}
    for s in sightings:
        groups.setdefault(uf.find(s["id"]), []).append(s["id"])
    return {
        "CMP-" + hashlib.sha1(root.encode()).hexdigest()[:8].upper(): sorted(m)
        for root, m in groups.items()
    }


def link_reasons(a: dict, b: dict) -> list[str]:
    r = []
    if a["tokens"] & b["tokens"]:
        r.append("shared payment details")
    if {site_key(u) for u in a.get("urls", [])} & {site_key(u) for u in b.get("urls", [])} - {""}:
        r.append("same website")
    if a.get("text") and b.get("text") and jaccard(shingles(a["text"]), shingles(b["text"])) >= TEXT_SIMILARITY:
        r.append("same page template")
    return r
