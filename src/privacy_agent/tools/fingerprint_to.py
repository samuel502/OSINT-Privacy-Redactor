"""Second discovery source: fingerprint.to.

holehe resolves ~121 sign-up flows and, even working, tops out at a handful of accounts.
fingerprint.to resolves 200+ platforms live and returns the profile fields behind each match
(name, username, location, bio, join/active dates), so it carries the audit.

It drives a real Chromium page because results stream in client-side. Selectors are anchored
on fingerprint.to's own hooks -- `data-platform-card-root`, the per-card `aria-label`, and the
favicon `url=` parameter that carries the platform domain -- rather than Tailwind class names.

Playwright is Apache-2.0, so importing it here is fine; only holehe needed a process boundary.
If playwright is missing we return "unavailable" and the rest of the audit still runs.

Set FINGERPRINT_HEADED=1 to watch the window, which lets you clear a bot check by hand.
"""
from __future__ import annotations

import os
import re
import sys
import time
from urllib.parse import unquote, urlparse

from ..schema import result, validate_email

SEARCH_URL = "https://fingerprint.to/email-search"
CARD = '[data-platform-card-root="true"]'
EMAIL_INPUT = 'input[inputmode="email"]'
SUBMIT = 'button[type="submit"]'
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

SETTLE_S = 6             # seconds with no new cards before we call the sweep done
POLL_MS = 1000
DEFAULT_TIMEOUT = 150

_LABEL = re.compile(r"^(?P<platform>.*?)\s+profile result(?:\s+for\s+@(?P<user>\S+))?\s*$")
_FAVICON_URL = re.compile(r"[?&]url=([^&]+)")


def _headed() -> bool:
    return os.environ.get("FINGERPRINT_HEADED", "").lower() in {"1", "true", "yes"}


def _domain_from_card(card) -> str:
    """The favicon URL parameter is the platform's own domain. Most reliable field on the card."""
    img = card.query_selector('img[src*="faviconV2"]')
    if not img:
        return ""
    m = _FAVICON_URL.search(img.get_attribute("src") or "")
    if not m:
        return ""
    host = urlparse(unquote(m.group(1))).netloc.lower()
    return host[4:] if host.startswith("www.") else host


def _parse_card(card) -> dict:
    entry = {"domain": _domain_from_card(card), "platform": "", "username": "",
             "name": "", "bio": "", "location": "", "fields": {}}
    m = _LABEL.match(card.get_attribute("aria-label") or "")
    if m:
        entry["platform"] = m.group("platform").strip()
        entry["username"] = (m.group("user") or "").strip()

    name_el = card.query_selector("p.font-semibold")
    if name_el:
        entry["name"] = (name_el.inner_text() or "").strip()

    for p in card.query_selector_all("p"):
        text = (p.inner_text() or "").strip()
        if not text:
            continue
        span = p.query_selector("span")
        head = (span.inner_text() if span else "").strip()
        if head.endswith(":"):                      # "Location: Berlin" style rows
            key = head[:-1].strip().lower()
            value = text[len(head):].strip()
            if key and value:
                entry["fields"][key] = value
                if key == "location":
                    entry["location"] = value
        elif "line-clamp" in (p.get_attribute("class") or ""):
            entry["bio"] = text
        elif text.startswith("@") and not entry["username"]:
            entry["username"] = text.lstrip("@")
    return entry


def _wait_for_stream(page, timeout: int) -> int:
    """Results arrive one at a time. Wait until the card count stops growing."""
    deadline = time.time() + timeout
    count, stable = 0, time.time()
    while time.time() < deadline:
        page.wait_for_timeout(POLL_MS)
        n = len(page.query_selector_all(CARD))
        if n != count:
            count, stable = n, time.time()
        elif n and (time.time() - stable) >= SETTLE_S:
            break
    return count


def _expand_all(page) -> None:
    """Cards hide extra fields behind a <details>. Open them, then let them fill in."""
    for summary in page.query_selector_all("details > summary"):
        try:
            summary.click(timeout=1200)
        except Exception:  # noqa: BLE001 - a card can scroll out from under the click
            pass
    page.wait_for_timeout(2000)


def fingerprint_probe(email: str, headed: bool | None = None,
                      timeout: int = DEFAULT_TIMEOUT) -> dict:
    email = validate_email(email)
    headed = _headed() if headed is None else headed
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return result("unavailable",
                      {"sources": {"fingerprint.to": "missing (pip install playwright)"}},
                      "fingerprint.to",
                      error="playwright not installed. Run: pip install playwright "
                            "&& playwright install chromium")

    pw = None
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=not headed)
        page = browser.new_page(viewport={"width": 1440, "height": 1100}, user_agent=UA)
        page.goto(SEARCH_URL, wait_until="domcontentloaded", timeout=45_000)
        page.wait_for_selector(EMAIL_INPUT, timeout=25_000)
        page.fill(EMAIL_INPUT, email)
        page.click(SUBMIT)
        _wait_for_stream(page, timeout)
        _expand_all(page)

        best = {}
        for card in page.query_selector_all(CARD):
            e = _parse_card(card)
            key = e["domain"] or e["platform"].lower()
            if not key:
                continue
            if key not in best or len(e["fields"]) > len(best[key]["fields"]):
                best[key] = e
        profiles = sorted(best.values(), key=lambda e: (e["domain"] or e["platform"]).lower())
        domains = sorted({e["domain"] for e in profiles if e["domain"]})

        if profiles:
            note = (f"{len(profiles)} profile(s) resolved. Fields come from fingerprint.to's "
                    "live sweep; a matching address is a strong lead, not proof it is the "
                    "same person.")
        else:
            note = ("No result cards found. If a bot check appeared, re-run with "
                    "FINGERPRINT_HEADED=1 so you can clear it.")
        return result("ok", {"profiles": profiles, "domains": domains,
                             "sources": {"fingerprint.to": "ok"}}, "fingerprint.to", note=note)
    except Exception as e:  # noqa: BLE001
        return result("unavailable",
                      {"sources": {"fingerprint.to": f"error: {type(e).__name__}"}},
                      "fingerprint.to", error=f"{type(e).__name__}: {e}")
    finally:
        if pw:
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass
            pw.stop()


if __name__ == "__main__":
    import json
    print(json.dumps(fingerprint_probe(sys.argv[1]), indent=2, default=str))
