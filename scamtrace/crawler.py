"""Follow a scam advert from its landing page to the payment step.

A headless browser opens the ad's landing URL and clicks through the
funnel (Buy / Checkout / Register / Deposit ...) until it reaches a page
that shows payment details, or runs out of steps. Forms are filled only
with an obviously synthetic decoy profile and never with real data.

Every step is recorded (URL, time, screenshot, HTML hash) so the result
can go into an evidence pack.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

from .extract import Finding, extract

FUNNEL_WORDS = re.compile(
    r"\b(buy|order|checkout|check out|pay|payment|basket|proceed|continue|"
    r"invest|deposit|fund (?:your )?account|get started|start (?:now|earning)|"
    r"register|sign up|join|claim|confirm|complete|submit|next|"
    r"(?:create|open) (?:an? |my |your )?account|offer|deal|shop now|view)\b",
    re.I,
)
AVOID_WORDS = re.compile(
    r"\b(privacy|terms|cookie|about|contact|faq|login|log in|help)\b", re.I
)

# Clearly fictitious: the .invalid TLD cannot exist, the number is an
# Ofcom drama-reserved range.
DECOY = {
    "name": "Alex Decoy",
    "first": "Alex",
    "last": "Decoy",
    "email": "alex.decoy@example.invalid",
    "phone": "07700900123",
    "postcode": "ZZ99 9ZZ",
    "address": "1 Test Street",
    "city": "Testville",
}


@dataclass
class Step:
    url: str
    at: str
    screenshot: str
    html_sha256: str
    action: str
    findings: int = 0


@dataclass
class CrawlResult:
    ad: dict
    steps: list[Step] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    text: str = ""  # page text across the funnel, for clustering/classifying
    final_text: str = ""  # text of the last page reached (the payment step)
    evidence_dir: Path | None = None
    error: str | None = None

    @property
    def final_screenshot(self) -> Path | None:
        if not self.steps or self.evidence_dir is None:
            return None
        p = self.evidence_dir / self.steps[-1].screenshot
        return p if p.exists() else None

    @property
    def final_url(self) -> str:
        return self.steps[-1].url if self.steps else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fill_forms(page) -> bool:
    filled = False
    for el in page.query_selector_all("input, select, textarea"):
        try:
            if not el.is_visible() or not el.is_enabled():
                continue
            kind = (el.get_attribute("type") or "text").lower()
            hint = " ".join(filter(None, [
                el.get_attribute("name"), el.get_attribute("id"),
                el.get_attribute("placeholder"), el.get_attribute("autocomplete"),
            ])).lower()
            if kind in ("hidden", "submit", "button", "file", "password"):
                continue
            if kind in ("checkbox", "radio"):
                if not el.is_checked():
                    el.check()
                continue
            if el.evaluate("e => e.tagName") == "SELECT":
                opts = el.evaluate("e => [...e.options].map(o => o.value).filter(Boolean)")
                if opts:
                    el.select_option(opts[0])
                continue
            # Never type anything that looks like card or bank data.
            if re.search(r"card|cvv|cvc|iban|sort|account|expiry|pin", hint):
                continue
            value = next((DECOY[k] for k in sorted(DECOY, key=len, reverse=True)
                          if k in hint), None)
            if value is None:
                value = DECOY["email"] if kind == "email" else (
                    DECOY["phone"] if kind == "tel" else (
                        "100" if kind == "number" else DECOY["name"]))
            if not el.input_value():
                el.fill(value)
                filled = True
        except PWError:
            continue
    return filled


def _next_target(page, visited: set[str]):
    candidates = page.query_selector_all(
        "a[href], button, input[type=submit], [role=button]"
    )
    scored = []
    for el in candidates:
        try:
            if not el.is_visible():
                continue
            label = (el.inner_text() or el.get_attribute("value") or "").strip()
            href = el.get_attribute("href") or ""
            if not label or AVOID_WORDS.search(label):
                continue
            if href.startswith(("mailto:", "tel:", "#")) and href != "#":
                continue
            m = FUNNEL_WORDS.search(label)
            if not m:
                continue
            key = label.lower() + "|" + href
            if key in visited:
                continue
            scored.append((m.start(), len(label), key, el, label))
        except PWError:
            continue
    if not scored:
        return None
    scored.sort(key=lambda t: (t[0], t[1]))
    _, _, key, el, label = scored[0]
    visited.add(key)
    return el, label


def crawl(ad: dict, evidence_dir: Path, max_steps: int = 6,
          timeout_ms: int = 15000) -> CrawlResult:
    """ad needs at least: ad_id, landing_url. Optional: platform, ad_text."""
    res = CrawlResult(ad=ad, evidence_dir=evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    seen_tokens: set[str] = set()
    texts: list[str] = [ad.get("ad_text", "")]
    visited: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36"),
            viewport={"width": 412, "height": 915},
            accept_downloads=False,
        )
        page = ctx.new_page()
        try:
            page.goto(ad["landing_url"], timeout=timeout_ms, wait_until="networkidle")
            action = "open landing page"
            for i in range(max_steps):
                page.wait_for_timeout(300)  # let late scripts render details
                html = page.content()
                shot = evidence_dir / f"{ad['ad_id']}_step{i}.png"
                page.screenshot(path=str(shot), full_page=True)
                new = [f for f in extract(html, page.url)
                       if f.identifier.token not in seen_tokens]
                for f in new:
                    seen_tokens.add(f.identifier.token)
                res.findings.extend(new)
                texts.append(page.inner_text("body"))
                res.steps.append(Step(
                    url=page.url, at=_now(), screenshot=shot.name,
                    html_sha256=hashlib.sha256(html.encode()).hexdigest(),
                    action=action, findings=len(new),
                ))
                if new and i > 0:
                    break  # reached the payment step
                filled = _fill_forms(page)
                target = _next_target(page, visited)
                if not target:
                    break
                el, label = target
                action = f"click '{label[:40]}'" + (" (decoy form)" if filled else "")
                try:
                    with page.expect_navigation(timeout=4000, wait_until="networkidle"):
                        el.click()
                except PWError:
                    pass  # same-page reveal (JS) rather than navigation
        except PWError as e:
            res.error = str(e).splitlines()[0]
        finally:
            browser.close()

    res.text = "\n".join(texts)
    res.final_text = texts[-1] if len(texts) > 1 else ""
    return res
