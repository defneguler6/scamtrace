"""TikTok ads from the official Commercial Content Library API.

The Commercial Content Library covers paid ads shown in the EEA,
Switzerland and the UK. API access needs a TikTok developer account and
an approved Commercial Content API application (TIKTOK_CLIENT_KEY,
TIKTOK_CLIENT_SECRET). See https://developers.tiktok.com/products/commercial-content-api

Known limits: destination URLs are often missing, and some ad IDs have no
metadata, so the AI reads the ad's image or video cover to find where it
sends people.

Endpoint paths and field names follow TikTok's published docs at the time
of writing. Verify them against the current docs when you first get access.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import httpx

from ..social import SocialItem

TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
QUERY_URL = "https://open.tiktokapis.com/v2/research/adlib/ad/query/"
FIELDS = ",".join([
    "ad.id", "ad.first_shown_date", "ad.last_shown_date", "ad.status",
    "ad.image_urls", "ad.videos", "ad.reach", "ad.landing_page_url",
    "advertiser.business_id", "advertiser.business_name", "advertiser.paid_for_by",
])


def get_token(client: httpx.Client | None = None) -> str:
    key, secret = os.environ.get("TIKTOK_CLIENT_KEY"), os.environ.get("TIKTOK_CLIENT_SECRET")
    if not key or not secret:
        raise RuntimeError("set TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET")
    client = client or httpx.Client(timeout=30)
    r = client.post(TOKEN_URL, data={"client_key": key, "client_secret": secret,
                                     "grant_type": "client_credentials"})
    body = r.json()
    if "access_token" not in body:
        raise RuntimeError(f"TikTok token error: {body}")
    return body["access_token"]


def parse(rec: dict, client: httpx.Client | None = None,
          download_images: bool = True) -> SocialItem:
    ad = rec.get("ad") or {}
    adv = rec.get("advertiser") or {}
    images: list[bytes] = []
    urls = list(ad.get("image_urls") or [])
    for v in ad.get("videos") or []:
        if isinstance(v, dict) and v.get("cover_image_url"):
            urls.append(v["cover_image_url"])
    if download_images and client is not None:
        for u in urls[:2]:
            try:
                r = client.get(u)
                if r.status_code == 200:
                    images.append(r.content)
            except httpx.HTTPError:
                pass
    landing = [ad["landing_page_url"]] if ad.get("landing_page_url") else []
    text = "\n".join(filter(None, [ad.get("title"), ad.get("text"), ad.get("description")]))
    return SocialItem(
        platform="tiktok",
        source="tiktok_ccl",
        source_id=str(ad.get("id")),
        text=text,
        handle=adv.get("business_name") or "",
        landing_urls=landing,
        images=images,
        first_seen=str(ad.get("first_shown_date") or ""),
    )


def search(term: str, country: str = "GB", days: int = 30, max_count: int = 50,
           token: str | None = None, client: httpx.Client | None = None) -> list[SocialItem]:
    client = client or httpx.Client(timeout=30)
    token = token or get_token(client)
    until = date.today()
    since = until - timedelta(days=days)
    body = {
        "filters": {
            "ad_published_date_range": {"min": since.strftime("%Y%m%d"),
                                        "max": until.strftime("%Y%m%d")},
            "country_code": country,
        },
        "search_term": term,
        "max_count": min(max_count, 50),
    }
    items: list[SocialItem] = []
    while len(items) < max_count:
        r = client.post(QUERY_URL, params={"fields": FIELDS}, json=body,
                        headers={"Authorization": f"Bearer {token}"})
        out = r.json()
        err = out.get("error") or {}
        if err.get("code") not in (None, "ok"):
            raise RuntimeError(f"TikTok API error: {err.get('message')}")
        data = out.get("data") or {}
        items += [parse(a, client) for a in data.get("ads", [])]
        if not data.get("has_more") or not data.get("search_id"):
            break
        body["search_id"] = data["search_id"]
    return items[:max_count]
