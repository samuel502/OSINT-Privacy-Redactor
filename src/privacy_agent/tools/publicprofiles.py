"""Tool: public_profiles. Profiles the owner of an email chose to publish. Free, no key.

Two sources, both public APIs:
  * Gravatar: a profile keyed by the MD5 of the email. It can list the owner's linked accounts.
  * GitHub: commits whose author email matches. GitHub itself says which account (if any) owns them.
    A hit also tells the owner that the address is visible in their public commits.

Honesty: a source that cannot answer (rate limit, offline) is reported as unknown, never as "none".
Untrusted text rule: only a short whitelist of fields is kept and each value is capped. Bios and
free text are dropped.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from ..schema import result, validate_email

SOURCE = "gravatar+github"
UA = {"User-Agent": "privacy-agent/0.1", "Accept": "application/json"}
MAX_LINKED = 12


def _get_json(url: str, timeout: int = 8):
    """Returns (status_code, parsed_json_or_None). status 0 = could not reach."""
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:  # noqa: BLE001
        return 0, None


def _https(u, n=300) -> str:
    return u[:n] if isinstance(u, str) and u.startswith("https://") else ""


def _txt(v, n=60) -> str:
    return str(v)[:n] if isinstance(v, (str, int)) else ""


def gravatar(email: str) -> tuple[str, list]:
    """(state, profiles) with state in found | none | unknown."""
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()  # Gravatar's scheme
    code, js = _get_json(f"https://www.gravatar.com/{digest}.json")
    if code == 404:
        return "none", []
    entry = ((js or {}).get("entry") or [None])[0] if code == 200 else None
    if not isinstance(entry, dict):
        return "unknown", []
    base = {"site": "Gravatar", "category": "Profile", "url": _https(entry.get("profileUrl")),
            "profile_url": _https(entry.get("profileUrl")), "avatar": _https(entry.get("thumbnailUrl")),
            "details": {k: v for k, v in (("name", _txt(entry.get("displayName"))),
                                          ("username", _txt(entry.get("preferredUsername")))) if v},
            "via": "gravatar", "label": "public_profile"}
    out = [base]
    for acc in (entry.get("accounts") or [])[:MAX_LINKED]:
        if not isinstance(acc, dict):
            continue
        url = _https(acc.get("url"))
        name = _txt(acc.get("shortname") or acc.get("domain"))
        if url and name:
            out.append({"site": name.capitalize(), "category": "Linked on Gravatar", "url": url,
                        "profile_url": url, "avatar": "", "via": "gravatar",
                        "details": ({"username": _txt(acc.get("username"))} if acc.get("username") else {}),
                        "label": "linked_profile", "verified": str(acc.get("verified")).lower() == "true"})
    return "found", out


def github(email: str) -> tuple[str, list]:
    q = urllib.parse.quote(f"author-email:{email}")
    code, js = _get_json(f"https://api.github.com/search/commits?q={q}&per_page=10")
    if code != 200 or not isinstance(js, dict):
        return "unknown", []
    seen, out = set(), []
    for it in js.get("items", []):
        a = it.get("author") if isinstance(it, dict) else None
        if not isinstance(a, dict) or not a.get("login"):
            continue
        login = _txt(a["login"], 40)
        if login.lower() in seen:
            continue
        seen.add(login.lower())
        out.append({"site": "GitHub", "category": "Dev", "url": _https(a.get("html_url")),
                    "profile_url": _https(a.get("html_url")), "avatar": _https(a.get("avatar_url")),
                    "details": {"username": login}, "via": "github", "label": "public_profile",
                    "note": "This email appears in public commits attributed to this account."})
    return ("found" if out else "none"), out


def public_profiles(email: str) -> dict:
    email = validate_email(email)
    states, profiles = {}, []
    for name, fn in (("gravatar", gravatar), ("github", github)):
        state, found = fn(email)
        states[name] = state
        profiles += found
    if all(v == "unknown" for v in states.values()):
        return result("error", {"sources": states}, SOURCE,
                      error="Neither Gravatar nor GitHub answered (rate limit or offline).")
    note = "Only profiles the owner published. 'none' means that source had nothing for this email."
    if "unknown" in states.values():
        note += " " + ", ".join(k for k, v in states.items() if v == "unknown") + " did not answer and is NOT counted as none."
    return result("ok", {"sources": states, "profiles": profiles}, SOURCE, note=note)
