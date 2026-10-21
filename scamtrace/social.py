"""TikTok / Instagram pipeline.

A SocialItem is one post or ad, from an official ad library or from a
submission (a link plus screenshots a payment firm or user sends in).

    item ─▶ AI reads caption + screenshots ─▶ payment details, contacts,
            red flags, scam type
         ─▶ follow any off-platform link (link in bio, ad destination)
            with the crawler ─▶ AI reads the payment page incl. screenshot
         ─▶ store ─▶ campaigns link posts to sites, accounts and wallets

ScamTrace never scrapes TikTok or Instagram themselves: it uses their
official ad libraries and content people submit. The crawler only visits
the off-platform scam sites the posts point to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import ai as ai_mod
from . import identifiers as ids
from .crawler import CrawlResult, crawl
from .extract import Finding, extract

PLATFORM_HOSTS = {
    "tiktok": ("tiktok.com", "vm.tiktok.com"),
    "instagram": ("instagram.com", "instagr.am"),
    "facebook": ("facebook.com", "fb.com", "fb.me", "m.facebook.com"),
}
# Never crawled: the platforms themselves and chat apps.
NO_CRAWL = tuple(h for hs in PLATFORM_HOSTS.values() for h in hs) + (
    "threads.net", "x.com", "twitter.com", "youtube.com", "youtu.be",
    "wa.me", "whatsapp.com", "t.me", "telegram.me", "snapchat.com")


@dataclass
class SocialItem:
    platform: str                 # tiktok | instagram | facebook | other
    source: str                   # meta_ad_library | tiktok_ccl | submission
    source_id: str
    text: str = ""                # caption / ad copy / pasted text
    post_url: str = ""
    handle: str = ""              # account or advertiser name
    landing_urls: list[str] = field(default_factory=list)
    images: list[bytes] = field(default_factory=list)
    snapshot_url: str = ""
    first_seen: str = ""

    @property
    def sighting_id(self) -> str:
        return f"{self.platform}:{self.source_id}"


def platform_of(url: str) -> str:
    host = urlsplit(url if "://" in url else "https://" + url).netloc.lower()
    host = host.removeprefix("www.")
    for p, hosts in PLATFORM_HOSTS.items():
        if any(host == h or host.endswith("." + h) for h in hosts):
            return p
    return "other"


def _normalise_link(u: str) -> str | None:
    u = u.strip().rstrip(".,);")
    if not u:
        return None
    if not re.match(r"https?://", u, re.I):
        if not re.match(r"[\w-]+(\.[\w-]+)+(/|$)", u):
            return None
        u = "https://" + u
    host = urlsplit(u).netloc.lower().removeprefix("www.")
    if not host or any(host == h or host.endswith("." + h) for h in NO_CRAWL):
        return None
    if ids.payment_link(u):
        return None  # a payment link is an identifier, not a site to crawl
    return u


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", s)[:60]


def enrich_crawl(r: CrawlResult, analyser) -> tuple[dict | None, list[Finding], list[dict]]:
    """AI pass over the page a crawl ended on (catches details in images)."""
    if not r.steps or analyser is None:
        return None, [], []
    shot = r.final_screenshot
    images = [shot.read_bytes()] if shot and analyser.engine != "heuristic" else []
    analysis = analyser.analyse("payment_page", r.final_text, images,
                                {"url": r.final_url})
    found, unverified = ai_mod.payment_findings(analysis, r.final_url)
    analysis["unverified_payment_details"] = unverified
    return analysis, found, unverified


def process(item: SocialItem, store, evidence_dir: Path, analyser=None,
            follow_links: bool = True, max_links: int = 2,
            post_ai: dict | None = None) -> dict:
    analyser = analyser or ai_mod.from_env()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    sid = item.sighting_id

    media = []
    for i, img in enumerate(item.images[:4]):
        name = f"{_safe(sid)}_post{i}.png"
        (evidence_dir / name).write_bytes(img)
        media.append(name)

    # 1. The post itself
    post_ai = post_ai or analyser.analyse(
        "social_post", item.text, item.images,
        {"platform": item.platform, "account": item.handle,
         "post_url": item.post_url, "first_seen": item.first_seen})
    url = item.post_url or item.snapshot_url
    findings = extract(item.text, url)
    pay, unverified = ai_mod.payment_findings(post_ai, url)
    contacts, links = ai_mod.contact_findings(post_ai, url)
    findings += pay + contacts
    post_ai["unverified_payment_details"] = unverified
    h = ids.social_handle(item.platform, item.handle)
    if h:
        findings.append(Finding(h, f"Posted by {h.masked}", url))

    # 2. Off-platform links: ad destination, link in bio, links in caption
    candidates = list(item.landing_urls) + links + re.findall(
        r"(?:https?://|www\.)[^\s\"'<>]+", item.text or "")
    to_follow = []
    for u in candidates:
        n = _normalise_link(u)
        if n and n not in to_follow:
            to_follow.append(n)

    steps, crawl_text, page_ai, final_url, error = [], [], [], "", None
    if follow_links:
        for i, u in enumerate(to_follow[:max_links]):
            r = crawl({"ad_id": f"{_safe(sid)}_link{i}", "landing_url": u,
                       "ad_text": item.text}, evidence_dir)
            steps += [s.__dict__ for s in r.steps]
            findings += r.findings
            crawl_text.append(r.text)
            final_url = final_url or r.final_url
            error = error or r.error
            a, extra, _ = enrich_crawl(r, analyser)
            if a:
                a["url"] = r.final_url
                page_ai.append(a)
                findings += extra

    ai_record = {**post_ai, "landing_pages": page_ai}
    store.save(
        sid, "social", findings,
        text="\n".join([item.text] + crawl_text), ai=ai_record,
        platform=item.platform, post_url=item.post_url or item.snapshot_url,
        handle=item.handle, ad_text=item.text,
        landing_url=to_follow[0] if to_follow else None,
        final_url=final_url or None, steps=steps, media=media, error=error)

    payment = [f for f in findings if f.identifier.kind in ids.PAYMENT_KINDS]
    return {
        "sighting_id": sid,
        "campaign_id": store.campaign_of(sid),
        "verdict": post_ai.get("verdict"),
        "scam_likelihood": post_ai.get("scam_likelihood"),
        "scam_type": post_ai.get("scam_type"),
        "summary": post_ai.get("summary"),
        "engine": post_ai.get("engine"),
        "links_followed": to_follow[:max_links] if follow_links else [],
        "payment_details": _summ(payment),
        "contacts": _summ([f for f in findings if f.identifier.kind not in ids.PAYMENT_KINDS]),
        "unverified_payment_details": unverified,
    }


def _summ(fs):
    seen, out = set(), []
    for f in fs:
        if f.identifier.token not in seen:
            seen.add(f.identifier.token)
            out.append({"type": f.identifier.kind, "masked": f.identifier.masked})
    return out
