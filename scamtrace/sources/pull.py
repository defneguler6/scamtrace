"""Pull ads from the official libraries and run them through the pipeline.

    python -m scamtrace.sources.pull meta   "ai trading" --countries GB,IE
    python -m scamtrace.sources.pull tiktok "clearance sale" --country IE

Only ads the AI rates at or above --min-likelihood are followed to their
landing page and stored, so legitimate advertisers are not kept.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .. import ai
from ..social import process
from ..store import Store


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("library", choices=["meta", "tiktok"])
    p.add_argument("terms")
    p.add_argument("--countries", default="GB,IE", help="meta: comma-separated")
    p.add_argument("--country", default="IE",
                   help="tiktok: one EU country code (the API covers EU countries only)")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--min-likelihood", type=float, default=0.5)
    p.add_argument("--list", action="store_true",
                   help="only list the ads found: no AI, no website visits, nothing stored")
    a = p.parse_args(argv)

    try:
        if a.library == "meta":
            from .meta_ad_library import search
            items = search(a.terms, countries=a.countries.split(","), limit=a.limit)
        else:
            from .tiktok_ccl import search
            items = search(a.terms, country=a.country, max_count=a.limit,
                           download_images=not a.list)
    except RuntimeError as e:
        print(f"Could not fetch ads.\n{e}")
        raise SystemExit(1)

    if a.list:
        print(f"{len(items)} ads from {a.library}:")
        for it in items:
            if a.library == "tiktok":
                media = f"{len(it.image_urls)} image(s), {len(it.video_urls)} video(s)"
                print(f"- {it.source_id:<20} {it.handle[:32]:<32} first shown "
                      f"{it.first_seen or '?':<9} {media}")
            else:
                text = " ".join(it.text.split())[:110]
                links = ", ".join(it.landing_urls) or "no link"
                print(f"- {it.platform:<9} {it.handle[:28]:<28} {text}  [{links}]")
        return

    store = Store(os.environ.get("SCAMTRACE_DB", "scamtrace.db"))
    evidence = Path(os.environ.get("SCAMTRACE_EVIDENCE", "evidence"))
    analyser = ai.from_env()
    print(f"{len(items)} ads from {a.library}; analyser: {analyser.engine}")
    kept = 0
    for it in items:
        quick = analyser.analyse("social_post", it.text, it.images,
                                 {"platform": it.platform, "account": it.handle})
        score = quick.get("scam_likelihood", 0)
        if score < a.min_likelihood:
            continue
        r = process(it, store, evidence, analyser, post_ai=quick)
        kept += 1
        print(f"{r['sighting_id']}: {r['verdict']} {score:.2f} {r['scam_type']} "
              f"-> {r['campaign_id']}  payment details: {len(r['payment_details'])}")
    print(f"kept {kept} of {len(items)}")


if __name__ == "__main__":
    main()
