"""SQLite store for sightings, identifiers and campaigns.

Only keyed hashes and masked forms of identifiers are stored.

Sighting sources:
  ad_crawl       an advert landing URL followed by the crawler
  social         a TikTok / Instagram / Facebook post or ad (+ any crawl of
                 the off-platform link it points to)
  victim_report  text a victim gave their payment firm
  partner        intelligence from a partner
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import cluster
from .classify import classify
from .extract import Finding, scrub

ADVERT_SOURCES = {"ad_crawl", "social"}

COLUMNS = ["id", "source", "platform", "post_url", "handle", "ad_text",
           "landing_url", "final_url", "seen_at", "scam_type", "signals",
           "pressure", "steps", "media", "text", "error", "ai"]

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS sightings (
    id TEXT PRIMARY KEY,
    {", ".join(c + " TEXT" for c in COLUMNS[1:])}
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

JSON_COLS = ("signals", "pressure", "steps", "media", "ai")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        have = {r[1] for r in self.db.execute("PRAGMA table_info(sightings)")}
        for c in COLUMNS:  # upgrade databases made by older versions
            if c not in have:
                self.db.execute(f"ALTER TABLE sightings ADD COLUMN {c} TEXT")
        self.db.commit()

    # ------------------------------------------------------------ writes

    def save(self, sid: str, source: str, findings: list[Finding], *,
             text: str = "", ai: dict | None = None, **fields):
        cls = classify(text)
        scam_type = cls["scam_type"]
        if ai and ai.get("engine") not in (None, "heuristic") and ai.get("scam_type"):
            scam_type = ai["scam_type"] if ai["scam_type"] != "none" else "unknown"
        row = {c: None for c in COLUMNS}
        row.update(fields)
        text = scrub(text)
        row["ad_text"] = scrub(row["ad_text"])
        ai = _scrub_obj(ai)
        row.update(id=sid, source=source, seen_at=_now(), scam_type=scam_type,
                   signals=cls["signals"], pressure=cls["pressure_tactics"],
                   text=text, ai=ai)
        for c in JSON_COLS:
            row[c] = json.dumps(row[c] if row[c] is not None else [] if c != "ai" else None)
        self.db.execute(
            f"INSERT OR REPLACE INTO sightings ({','.join(COLUMNS)}) "
            f"VALUES ({','.join('?' * len(COLUMNS))})", [row[c] for c in COLUMNS])
        self.db.execute("DELETE FROM identifiers WHERE sighting_id=?", (sid,))
        for f in findings:
            self.db.execute(
                "INSERT OR IGNORE INTO identifiers VALUES (?,?,?,?,?,?,?)",
                (sid, f.identifier.kind, f.identifier.token, f.identifier.masked,
                 f.snippet, f.url, row["seen_at"]))
        self.db.commit()
        self.recluster()

    def save_crawl(self, r, ai: dict | None = None, extra: list[Finding] = ()):
        self.save(
            r.ad["ad_id"], "ad_crawl", _dedupe(list(r.findings) + list(extra)),
            text=r.text, ai=ai, platform=r.ad.get("platform"),
            ad_text=r.ad.get("ad_text"), landing_url=r.ad["landing_url"],
            final_url=r.final_url, steps=[s.__dict__ for s in r.steps], error=r.error)

    def save_report(self, sid: str, text: str, findings: list[Finding],
                    source: str = "victim_report", url: str = ""):
        self.save(sid, source, findings, text=text, landing_url=url, final_url=url)

    def recluster(self):
        rows = self.db.execute(
            "SELECT id, source, landing_url, final_url, text FROM sightings").fetchall()
        tokens: dict[str, set] = {}
        for t in self.db.execute("SELECT sighting_id, token FROM identifiers"):
            tokens.setdefault(t["sighting_id"], set()).add(t["token"])
        sightings = [{
            "id": r["id"],
            "tokens": tokens.get(r["id"], set()),
            # Reports link only through identifiers: their text is free-form
            # and their URL may be a platform rather than a scam site.
            "urls": [u for u in (r["landing_url"], r["final_url"]) if u]
                    if r["source"] in ADVERT_SOURCES else [],
            "text": r["text"] if r["source"] in ADVERT_SOURCES else "",
        } for r in rows]
        groups = cluster.campaigns(sightings)
        self.db.execute("DELETE FROM campaign_members")
        self.db.executemany(
            "INSERT INTO campaign_members VALUES (?,?)",
            [(cid, sid) for cid, members in groups.items() for sid in members])
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
            for k in JSON_COLS:
                s[k] = json.loads(s[k]) if s[k] else ([] if k != "ai" else None)
        adverts = [s for s in sightings if s["source"] in ADVERT_SOURCES]
        types = [s["scam_type"] for s in adverts if s["scam_type"] not in ("unknown", None)]
        return {
            "campaign_id": cid,
            "scam_type": max(set(types), key=types.count) if types else "unknown",
            "first_seen": sightings[0]["seen_at"],
            "last_seen": sightings[-1]["seen_at"],
            "sightings": sightings,
            "identifiers": idents,
            "payment_identifiers": [i for i in idents if i["kind"] in _payment_kinds()],
            "platforms": sorted({s["platform"] for s in adverts
                                 if s["source"] == "social" and s["platform"]}),
            "sites": sorted({cluster.site_key(u) for s in adverts
                             for u in (s["landing_url"], s["final_url"]) if u} - {""}),
        }

    def campaign_ids(self) -> list[str]:
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT campaign_id FROM campaign_members")]


def _scrub_obj(o):
    """Scrub every string inside an AI analysis before it is stored."""
    if isinstance(o, str):
        return scrub(o)
    if isinstance(o, list):
        return [_scrub_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: _scrub_obj(v) for k, v in o.items()}
    return o


def _payment_kinds():
    from .identifiers import PAYMENT_KINDS
    return PAYMENT_KINDS


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.identifier.token not in seen:
            seen.add(f.identifier.token)
            out.append(f)
    return out
