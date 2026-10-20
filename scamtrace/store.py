"""SQLite store for sightings, payment identifiers and campaigns.

Only keyed hashes and masked forms of identifiers are stored.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import cluster
from .classify import classify
from .crawler import CrawlResult
from .extract import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,          -- ad_crawl | victim_report | partner
    platform    TEXT,
    ad_text     TEXT,
    landing_url TEXT,
    final_url   TEXT,
    seen_at     TEXT NOT NULL,
    scam_type   TEXT,
    signals     TEXT,
    pressure    TEXT,
    steps       TEXT,
    text        TEXT,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS identifiers (
    sighting_id TEXT NOT NULL REFERENCES sightings(id),
    kind        TEXT NOT NULL,
    token       TEXT NOT NULL,
    masked      TEXT NOT NULL,
    snippet     TEXT,
    url         TEXT,
    seen_at     TEXT NOT NULL,
    PRIMARY KEY (sighting_id, token)
);
CREATE INDEX IF NOT EXISTS ix_identifiers_token ON identifiers(token);
CREATE TABLE IF NOT EXISTS campaign_members (
    campaign_id TEXT NOT NULL,
    sighting_id TEXT PRIMARY KEY
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------ writes

    def _save(self, sid, source, platform, ad_text, landing, final, steps,
              text, error, findings: list[Finding]):
        cls = classify(text)
        now = _now()
        self.db.execute(
            "INSERT OR REPLACE INTO sightings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, source, platform, ad_text, landing, final, now,
             cls["scam_type"], json.dumps(cls["signals"]),
             json.dumps(cls["pressure_tactics"]), json.dumps(steps), text, error),
        )
        for f in findings:
            self.db.execute(
                "INSERT OR IGNORE INTO identifiers VALUES (?,?,?,?,?,?,?)",
                (sid, f.identifier.kind, f.identifier.token, f.identifier.masked,
                 f.snippet, f.url, now),
            )
        self.db.commit()
        self.recluster()

    def save_crawl(self, r: CrawlResult):
        self._save(
            r.ad["ad_id"], "ad_crawl", r.ad.get("platform"), r.ad.get("ad_text"),
            r.ad["landing_url"], r.final_url,
            [s.__dict__ for s in r.steps], r.text, r.error, r.findings,
        )

    def save_report(self, sid: str, text: str, findings: list[Finding],
                    source: str = "victim_report", url: str = ""):
        self._save(sid, source, None, None, url, url, [], text, None, findings)

    def recluster(self):
        rows = self.db.execute("SELECT id, source, landing_url, final_url, text FROM sightings").fetchall()
        tokens: dict[str, set] = {}
        for t in self.db.execute("SELECT sighting_id, token FROM identifiers"):
            tokens.setdefault(t["sighting_id"], set()).add(t["token"])
        sightings = [{
            "id": r["id"],
            "tokens": tokens.get(r["id"], set()),
            # Victim reports link only through payment details: their text
            # is free-form and their URL may be a platform, not a scam site.
            "urls": [u for u in (r["landing_url"], r["final_url"]) if u]
                    if r["source"] == "ad_crawl" else [],
            "text": r["text"] if r["source"] == "ad_crawl" else "",
        } for r in rows]
        groups = cluster.campaigns(sightings)
        self.db.execute("DELETE FROM campaign_members")
        self.db.executemany(
            "INSERT INTO campaign_members VALUES (?,?)",
            [(cid, sid) for cid, members in groups.items() for sid in members],
        )
        self.db.commit()

    # ------------------------------------------------------------- reads

    def campaign_of(self, sighting_id: str) -> str | None:
        r = self.db.execute(
            "SELECT campaign_id FROM campaign_members WHERE sighting_id=?",
            (sighting_id,)).fetchone()
        return r["campaign_id"] if r else None

    def lookup(self, token: str) -> list[sqlite3.Row]:
        return self.db.execute(
            """SELECT i.*, s.source, cm.campaign_id FROM identifiers i
               JOIN sightings s ON s.id = i.sighting_id
               JOIN campaign_members cm ON cm.sighting_id = i.sighting_id
               WHERE i.token = ? ORDER BY i.seen_at""", (token,)).fetchall()

    def campaign(self, cid: str) -> dict | None:
        members = [r["sighting_id"] for r in self.db.execute(
            "SELECT sighting_id FROM campaign_members WHERE campaign_id=?", (cid,))]
        if not members:
            return None
        q = ",".join("?" * len(members))
        sightings = [dict(r) for r in self.db.execute(
            f"SELECT * FROM sightings WHERE id IN ({q}) ORDER BY seen_at", members)]
        idents = [dict(r) for r in self.db.execute(
            f"""SELECT kind, token, masked, MIN(seen_at) first_seen,
                       MAX(seen_at) last_seen, COUNT(*) sightings,
                       MIN(snippet) snippet, MIN(url) url
                FROM identifiers WHERE sighting_id IN ({q})
                GROUP BY token ORDER BY first_seen""", members)]
        for s in sightings:
            for k in ("signals", "pressure", "steps"):
                s[k] = json.loads(s[k] or "[]")
        types = [s["scam_type"] for s in sightings
                 if s["source"] == "ad_crawl" and s["scam_type"] != "unknown"]
        return {
            "campaign_id": cid,
            "scam_type": max(set(types), key=types.count) if types else "unknown",
            "first_seen": sightings[0]["seen_at"],
            "last_seen": sightings[-1]["seen_at"],
            "sightings": sightings,
            "identifiers": idents,
            "sites": sorted({cluster.site_key(u) for s in sightings
                             if s["source"] == "ad_crawl"
                             for u in (s["landing_url"], s["final_url"]) if u}),
        }

    def campaign_ids(self) -> list[str]:
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT campaign_id FROM campaign_members")]
