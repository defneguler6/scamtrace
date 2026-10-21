"""TikTok ads from the official Commercial Content API.

Access: an approved Commercial Content API project at developers.tiktok.com.
Put the project's client key and secret in .env as TIKTOK_CLIENT_KEY and
TIKTOK_CLIENT_SECRET. Docs:
https://developers.tiktok.com/doc/commercial-content-api-query-ads

What the API gives (October 2026):
  * ads shown in EU countries only (the website library also shows UK ads,
    the API does not yet), published after 1 October 2022
  * advertiser name, first/last shown dates, status, reach, image URLs and
    video URLs; NO ad text and NO destination link
  * at most 10 ads per request; paginate with search_id

Because there is no text or link, the AI has to read the ad's images (and,
on the roadmap, frames from its videos) to find the offer, where it sends
people and any payment details.
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
    "ad.image_urls", "ad.videos", "ad.reach",
    "advertiser.business_id", "advertiser.business_name", "advertiser.paid_for_by",
])
PAGE_SIZE = 10  # API maximum


def get_token(client: httpx.Client | None = None) -> str:
    key, secret = os.environ.get("TIKTOK_CLIENT_KEY"), os.environ.get("TIKTOK_CLIENT_SECRET")
    if not key or not secret:
        raise RuntimeError("set TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET in .env "
                           "(developers.tiktok.com/research -> your project -> eye icon)")
    client = client or httpx.Client(timeout=30)
    r = client.post(TOKEN_URL, data={"client_key": key, "client_secret": secret,
                                     "grant_type": "client_credentials"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    body = r.json()
    if "access_token" not in body:
        raise RuntimeError("TikTok token error: "
                           f"{body.get('error_description') or body.get('error') or body}"
                           "\n  -> check the client key and secret in .env")
    return body["access_token"]


def parse(rec: dict, client: httpx.Client | None = None,
          download_images: bool = True) -> SocialItem:
    ad = rec.get("ad") or {}
    adv = rec.get("advertiser") or {}
    images: list[bytes] = []
    if download_images and client is not None:
        for u in (ad.get("image_urls") or [])[:2]:
            try:
                r = client.get(u)
                if r.status_code == 200 and r.content:
                    images.append(r.content)
            except httpx.HTTPError:
                pass
    videos = [v.get("url") for v in ad.get("videos") or [] if isinstance(v, dict) and v.get("url")]
    reach = (ad.get("reach") or {}).get("unique_users_seen")
    # No ad text from the API: give the AI the facts it does have.
    facts = [f"Advertiser: {adv.get('business_name')}" if adv.get("business_name") else "",
             f"Paid for by: {adv.get('paid_by') or adv.get('paid_for_by')}"
             if (adv.get("paid_by") or adv.get("paid_for_by")) else "",
             f"Shown: {ad.get('first_shown_date')} to {ad.get('last_shown_date')}"
             if ad.get("first_shown_date") else "",
             f"Unique users reached: {reach}" if reach else "",
             f"Video ad ({len(videos)} video)" if videos else ""]
    item = SocialItem(
        platform="tiktok",
        source="tiktok_ccl",
        source_id=str(ad.get("id")),
        text="\n".join(f for f in facts if f),
        handle=adv.get("business_name") or "",
        landing_urls=[ad["landing_page_url"]] if ad.get("landing_page_url") else [],
        images=images,
        first_seen=str(ad.get("first_shown_date") or ""),
    )
    item.video_urls = videos
    item.image_urls = list(ad.get("image_urls") or [])
    return item


def search(term: str, country: str = "IE", days: int = 30, max_count: int = 30,
           token: str | None = None, client: httpx.Client | None = None,
           download_images: bool = True) -> list[SocialItem]:
    client = client or httpx.Client(timeout=30)
    token = token or get_token(client)
    until = date.today() - timedelta(days=1)  # the API requires a date before today
    since = until - timedelta(days=days)
    body = {
        "filters": {
            "ad_published_date_range": {"min": since.strftime("%Y%m%d"),
                                        "max": until.strftime("%Y%m%d")},
            "country_code": country,
        },
        "search_term": term[:50],
        "search_type": "fuzzy_phrase",
        "max_count": PAGE_SIZE,
    }
    items: list[SocialItem] = []
    while len(items) < max_count:
        r = client.post(QUERY_URL, params={"fields": FIELDS}, json=body,
                        headers={"Authorization": f"Bearer {token}",
                                 "Content-Type": "application/json"})
        out = r.json()
        err = out.get("error") or {}
        if err.get("code") not in (None, "ok"):
            hint = ""
            if "country" in (err.get("message") or "").lower():
                hint = "\n  -> the API covers EU countries only: try --country IE, FR or DE"
            raise RuntimeError(f"TikTok API error ({err.get('code')}): {err.get('message')}{hint}")
        data = out.get("data") or {}
        items += [parse(a, client, download_images) for a in data.get("ads", [])]
        more = data.get("has_more")
        if str(more).lower() != "true" or not data.get("search_id"):
            break
        body["search_id"] = data["search_id"]
    return items[:max_count]
