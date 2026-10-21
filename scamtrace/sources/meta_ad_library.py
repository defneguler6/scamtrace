"""Instagram and Facebook ads from Meta's official Ad Library API.

Access: a Meta developer app, identity confirmation for the Ad Library,
and an access token (META_ACCESS_TOKEN). See
https://www.facebook.com/ads/library/api

Coverage limits that matter for a UK product (check before relying on it):
  * Commercial (non-political) ads are returned for ads that reached the
    EU. Ads shown only in the UK are returned only if they are about
    social issues, elections or politics. Many scam campaigns target the
    UK and Ireland together, so searching ["GB", "IE"] helps, but UK-only
    scam ads may be missing.
  * The API gives ad text and a snapshot page, not the media files, and
    the destination URL is often missing; the link caption usually shows
    the display domain, which is used as the landing page.

Field names below follow the Graph API ads_archive endpoint. Verify them
against the current docs when you first get access.
"""

from __future__ import annotations

import json
import os
import re

import httpx

from ..social import SocialItem

GRAPH = "https://graph.facebook.com"
FIELDS = ",".join([
    "id", "page_id", "page_name", "ad_creative_bodies", "ad_creative_link_titles",
    "ad_creative_link_captions", "ad_creative_link_descriptions",
    "ad_delivery_start_time", "ad_snapshot_url", "publisher_platforms",
])

_DOMAIN = re.compile(r"^(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(/\S*)?$", re.I)


def parse(rec: dict) -> SocialItem:
    """One ads_archive record -> SocialItem."""
    bodies = rec.get("ad_creative_bodies") or []
    titles = rec.get("ad_creative_link_titles") or []
    descs = rec.get("ad_creative_link_descriptions") or []
    captions = rec.get("ad_creative_link_captions") or []
    text = "\n".join(dict.fromkeys(bodies + titles + descs))  # de-duplicated, ordered
    landings = []
    for c in captions:
        m = _DOMAIN.match(c.strip())
        if m:
            landings.append("https://" + m.group(1).lower() + (m.group(2) or ""))
    platforms = [p.lower() for p in rec.get("publisher_platforms") or []]
    platform = "instagram" if "instagram" in platforms else (
        "facebook" if "facebook" in platforms else (platforms[0] if platforms else "facebook"))
    return SocialItem(
        platform=platform,
        source="meta_ad_library",
        source_id=str(rec["id"]),
        text=text,
        handle=rec.get("page_name") or "",
        landing_urls=landings,
        snapshot_url=rec.get("ad_snapshot_url") or "",
        first_seen=rec.get("ad_delivery_start_time") or "",
    )


def search(terms: str, countries=("GB", "IE"), platforms=("INSTAGRAM",),
           token: str | None = None, limit: int = 200,
           client: httpx.Client | None = None) -> list[SocialItem]:
    token = token or os.environ.get("META_ACCESS_TOKEN")
    if not token:
        raise RuntimeError("set META_ACCESS_TOKEN (Meta Ad Library API access)")
    version = os.environ.get("META_GRAPH_VERSION", "v23.0")
    client = client or httpx.Client(timeout=30)
    url = f"{GRAPH}/{version}/ads_archive"
    params = {
        "search_terms": terms,
        "ad_reached_countries": json.dumps(list(countries)),
        "ad_type": "ALL",
        "ad_active_status": "ACTIVE",
        "publisher_platforms": json.dumps(list(platforms)),
        "fields": FIELDS,
        "limit": min(limit, 100),
        "access_token": token,
    }
    items: list[SocialItem] = []
    while url and len(items) < limit:
        resp = client.get(url, params=params)
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"Meta API error: {body['error'].get('message')}")
        items += [parse(r) for r in body.get("data", [])]
        url = (body.get("paging") or {}).get("next")
        params = None  # the next URL already carries the query
    return items[:limit]
