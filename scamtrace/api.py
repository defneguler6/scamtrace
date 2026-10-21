"""HTTP API for payment firms.

    POST /v1/payee/check            is this payee linked to a live scam campaign?
    POST /v1/sightings/social       a TikTok / Instagram post: link, caption, screenshots
    POST /v1/sightings/ad           crawl a scam advert landing page
    POST /v1/sightings/report       add a victim or partner report
    GET  /v1/campaigns              list campaigns
    GET  /v1/campaigns/{id}/evidence-pack?format=json|html

Run:  uvicorn scamtrace.api:app --reload
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

import base64
import binascii

from . import ai, evidence, identifiers
from .crawler import crawl
from .extract import extract
from .social import SocialItem, enrich_crawl, platform_of, process
from .store import ADVERT_SOURCES, Store

DB_PATH = os.environ.get("SCAMTRACE_DB", "scamtrace.db")
EVIDENCE_DIR = Path(os.environ.get("SCAMTRACE_EVIDENCE", "evidence"))
API_KEYS = set(os.environ.get("SCAMTRACE_API_KEYS", "demo-key").split(","))

app = FastAPI(
    title="ScamTrace",
    version="0.1.0",
    description="Links payees to live advert-originated scam campaigns.",
)
store = Store(DB_PATH)
analyser = ai.from_env()


def auth(x_api_key: str = Header(default="")):
    if x_api_key not in API_KEYS:
        raise HTTPException(401, "missing or invalid X-API-Key")


# ----------------------------------------------------------- payee check


class PayeeQuery(BaseModel):
    sort_code: str | None = Field(None, examples=["00-11-22"])
    account_number: str | None = Field(None, examples=["87654321"])
    iban: str | None = None
    wallet: str | None = None
    payment_link: str | None = None
    direction: Literal["inbound", "outbound"] = Field(
        "inbound",
        description="inbound: money arriving at your customer's account "
                    "(mule risk); outbound: your customer is about to pay.",
    )


ACTIONS = {
    ("high", "outbound"): "Hold the payment and speak to the customer: the "
        "payee is collecting money for a live scam campaign.",
    ("high", "inbound"): "Review the receiving account for mule activity "
        "before releasing funds; consider freezing pending investigation.",
    ("medium", "outbound"): "Show a specific scam warning and ask the "
        "customer how they found the payee.",
    ("medium", "inbound"): "Flag the account for enhanced monitoring.",
}


@app.post("/v1/payee/check", dependencies=[Depends(auth)])
def check_payee(q: PayeeQuery):
    ident = identifiers.from_query(q.model_dump())
    if ident is None:
        raise HTTPException(422, "provide one valid identifier: sort_code + "
                                 "account_number, iban, wallet or payment_link")
    rows = store.lookup(ident.token)
    if not rows:
        return {"match": False, "risk": "none", "identifier": ident.masked}
    if ident.kind not in identifiers.PAYMENT_KINDS:
        raise HTTPException(422, "not a payment identifier")
    from_ads = any(r["source"] in ADVERT_SOURCES for r in rows)
    risk = "high" if from_ads else "medium"
    cid = rows[0]["campaign_id"]
    c = store.campaign(cid)
    return {
        "match": True,
        "risk": risk,
        "identifier": ident.masked,
        "reason": ("Seen in scam adverts or posts, or on the payment pages they lead to"
                   if from_ads else "Reported by scam victims"),
        "first_seen": rows[0]["seen_at"],
        "last_seen": rows[-1]["seen_at"],
        "campaign": {
            "id": cid,
            "scam_type": c["scam_type"],
            "ads_and_posts_seen": sum(s["source"] in ADVERT_SOURCES for s in c["sightings"]),
            "victim_reports": sum(s["source"] not in ADVERT_SOURCES for s in c["sightings"]),
            "platforms": c["platforms"],
            "websites": len(c["sites"]),
            "linked_payment_details": len(c["payment_identifiers"]),
        },
        "recommended_action": ACTIONS[(risk, q.direction)],
        "evidence_pack": f"/v1/campaigns/{cid}/evidence-pack",
    }


# ------------------------------------------------------------ ingestion


class Ad(BaseModel):
    ad_id: str
    landing_url: str
    platform: str | None = None
    ad_text: str | None = None


@app.post("/v1/sightings/ad", dependencies=[Depends(auth)])
def ingest_ad(ad: Ad):
    r = crawl(ad.model_dump(), EVIDENCE_DIR)
    page_ai, extra, unverified = enrich_crawl(r, analyser)
    store.save_crawl(r, ai=page_ai, extra=extra)
    seen = {f.identifier.token for f in r.findings}
    r.findings += [f for f in extra if f.identifier.token not in seen]
    return {
        "ad_id": ad.ad_id,
        "campaign_id": store.campaign_of(ad.ad_id),
        "steps": len(r.steps),
        "payment_page": r.final_url,
        "payment_details": [{"type": f.identifier.kind, "masked": f.identifier.masked}
                            for f in r.findings],
        "unverified_payment_details": unverified,
        "ai_engine": analyser.engine,
        "error": r.error,
    }


class SocialPost(BaseModel):
    submission_id: str = Field(examples=["SUB-001"])
    platform: Literal["tiktok", "instagram", "facebook", "other"] | None = Field(
        None, description="Worked out from post_url if not given")
    post_url: str | None = Field(None, examples=["https://www.tiktok.com/@shop/video/123"])
    handle: str | None = Field(None, description="Account that posted it")
    text: str | None = Field(None, description="Caption or ad text, pasted")
    screenshots_b64: list[str] = Field(
        default_factory=list, description="Up to 4 screenshots, base64 PNG/JPEG")
    landing_urls: list[str] = Field(
        default_factory=list, description="Link in bio or ad destination, if known")
    follow_links: bool = True


@app.post("/v1/sightings/social", dependencies=[Depends(auth)])
def ingest_social(post: SocialPost):
    try:
        images = [base64.b64decode(b, validate=True) for b in post.screenshots_b64[:4]]
    except (binascii.Error, ValueError):
        raise HTTPException(422, "screenshots_b64 must be base64")
    if not (post.text or images or post.landing_urls):
        raise HTTPException(422, "send at least text, a screenshot or a link")
    item = SocialItem(
        platform=post.platform or (platform_of(post.post_url) if post.post_url else "other"),
        source="submission", source_id=post.submission_id, text=post.text or "",
        post_url=post.post_url or "", handle=post.handle or "",
        landing_urls=post.landing_urls, images=images)
    return process(item, store, EVIDENCE_DIR, analyser, follow_links=post.follow_links)


class Report(BaseModel):
    report_id: str
    text: str = Field(description="What the victim was told, pasted as text")
    url: str | None = None
    source: Literal["victim_report", "partner"] = "victim_report"


@app.post("/v1/sightings/report", dependencies=[Depends(auth)])
def ingest_report(rep: Report):
    findings = extract(rep.text, rep.url or "")
    store.save_report(rep.report_id, rep.text, findings, rep.source, rep.url or "")
    return {
        "report_id": rep.report_id,
        "campaign_id": store.campaign_of(rep.report_id),
        "payment_details": [{"type": f.identifier.kind, "masked": f.identifier.masked}
                            for f in findings],
    }


# ------------------------------------------------------------ campaigns


@app.get("/v1/campaigns", dependencies=[Depends(auth)])
def list_campaigns():
    out = []
    for cid in store.campaign_ids():
        c = store.campaign(cid)
        if not c["payment_identifiers"]:
            continue  # nothing a payment firm can act on
        out.append({"id": cid, "scam_type": c["scam_type"],
                    "platforms": c["platforms"],
                    "websites": len(c["sites"]),
                    "payment_details": len(c["payment_identifiers"]),
                    "last_seen": c["last_seen"]})
    return sorted(out, key=lambda c: c["last_seen"], reverse=True)


@app.get("/v1/campaigns/{cid}/evidence-pack", dependencies=[Depends(auth)])
def evidence_pack(cid: str, format: Literal["json", "html"] = "json"):
    c = store.campaign(cid)
    if not c:
        raise HTTPException(404, "unknown campaign")
    pack = evidence.build(c)
    if format == "html":
        return HTMLResponse(evidence.render_html(pack, EVIDENCE_DIR))
    return pack


@app.get("/health")
def health():
    return {"ok": True, "ai_engine": analyser.engine}
