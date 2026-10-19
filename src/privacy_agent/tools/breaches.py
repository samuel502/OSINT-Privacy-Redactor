"""Tool 2 (discovery, different data source): which known breaches include this email?

Uses the free XposedOrNot API (no key). Free tier is roughly 1 request/second.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from ..schema import result, validate_email

BASE = "https://api.xposedornot.com/v1/check-email/"
SOURCE = "xposedornot.com"


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

    names = sorted(set(_flatten(body.get("breaches"))))
    return result("ok", {"breach_count": len(names), "breaches": names}, SOURCE)
