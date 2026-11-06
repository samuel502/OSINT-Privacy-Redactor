"""Tool 2 (discovery, different data source): which known breaches include this email?

Uses the free XposedOrNot API (no key). Free tier is roughly 1 request/second.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from ..schema import result, validate_email

BASE = "https://api.xposedornot.com/v1/check-email/"
SOURCE = "xposedornot.com"
# Breach names are third-party text (security-framework.md section 1): short, plain names only.
MAX_BREACHES = 100
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._&'()+-]{0,59}")


def _flatten(x):
    if isinstance(x, str):
        return [x]
    if isinstance(x, (list, tuple)):
        return [s for item in x for s in _flatten(item)]
    return []


def breach_lookup(email: str) -> dict:
    email = validate_email(email)
    req = urllib.request.Request(BASE + urllib.parse.quote(email, safe=""),
                                 headers={"User-Agent": "privacy-agent/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return result("ok", {"breach_count": 0, "breaches": []}, SOURCE,
                          note="Not found in this dataset. Not proof the email was never exposed.")
        if e.code == 429:
            return result("error", source=SOURCE, error="Rate limited (free API ~1 req/s). Retry shortly.")
        return result("error", source=SOURCE, error=f"HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        return result("unavailable", source=SOURCE, error=f"Could not reach API: {e}")

    if not isinstance(body, dict) or "breaches" not in body:
        # A 200 we do not understand is not "no breaches".
        return result("error", source=SOURCE, error="Unexpected response shape from the breach API.")
    raw = sorted(set(_flatten(body.get("breaches"))))
    names = [n for n in raw if _NAME_RE.fullmatch(n)]
    dropped = len(raw) - len(names)
    note = None
    if len(names) > MAX_BREACHES:
        note = f"{len(names)} breaches; only the first {MAX_BREACHES} are listed."
    if dropped:
        note = (note + " " if note else "") + f"{dropped} breach name(s) had unexpected characters and were dropped."
    return result("ok", {"breach_count": len(names), "breaches": names[:MAX_BREACHES]}, SOURCE, note=note)
