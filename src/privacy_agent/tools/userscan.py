"""Tools: email_scan and username_scan (live lookups, powered by user-scanner, MIT).

user-scanner runs as a subprocess and writes JSON; we parse that JSON. Reasons:
  * a crash or hang in one of its ~2,800 site modules cannot take the app down;
  * its console output carries banners and promotional text, which never reach the model;
  * the tool keeps working if the package changes its internals, as long as the JSON stays.

What reaches the model is deliberately small. Profile fields come from third-party sites,
so they are untrusted text: only a short whitelist is kept, each value is capped, and
free-text fields such as bios are dropped (a bio could contain instructions aimed at the model).

Honesty rules carried into the output:
  * "Registered"/"Found" is a hit. "Not Registered"/"Not Found" is absence on that site only.
  * "Error" and "Skipped" are counted and reported, never turned into "not found".
  * Sites that may email the target a password-reset notice are skipped unless include_loud=True.
  * A username hit is only a "possible_match": the same handle can belong to someone else.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

from ..schema import result, validate_email

SOURCE = "user-scanner"
TIMEOUT_S = int(os.environ.get("USER_SCANNER_TIMEOUT", "280"))
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

HIT = {"registered", "found", "taken"}
ABSENT = {"not registered", "not found", "available"}
# Fields safe to show the model. Anything else (bio, about, description...) is dropped.
KEEP_EXTRA = ("name", "username", "joined", "created", "followers", "following", "location",
              "last_profile_update", "last_active", "last_seen", "has_public_page")
MAX_VALUE = 80
MAX_HITS = 60


def validate_username(username: str) -> str:
    username = (username or "").strip().lstrip("@")
    if not USERNAME_RE.match(username):  # also blocks leading '-' (CLI flag lookalikes)
        raise ValueError(f"Invalid username: {username!r}")
    return username


def _clean_extra(extra: dict | None) -> dict:
    out = {}
    for k, v in (extra or {}).items():
        if str(k).lower() in KEEP_EXTRA and isinstance(v, (str, int, float)):
            out[str(k).lower()] = str(v)[:MAX_VALUE]
    return out


def _avatar(media) -> str:
    """Profile picture link if the site gave one. https only, capped. Never fetched by us."""
    url = (media or {}).get("avatar") if isinstance(media, dict) else None
    if not (isinstance(url, str) and url.startswith("https://")) or "default" in url.lower():
        return ""  # sites return a grey placeholder when there is no real picture: not a profile picture
    return url[:300]


def parse_rows(rows: list[dict], kind: str) -> dict:
    """Turn user-scanner JSON rows into the compact summary the agent sees."""
    hits, counts = [], {"checked": 0, "absent": 0, "errors": 0, "skipped": 0}
    not_checked = {"error_sites": [], "skipped_sites": []}
    for r in rows:
        status = str(r.get("status", "")).strip().lower()
        site = str(r.get("site_name", ""))[:40]
        if status == "skipped":
            counts["skipped"] += 1
            if site and len(not_checked["skipped_sites"]) < 120:
                not_checked["skipped_sites"].append(site)
        elif status == "error":
            counts["errors"] += 1
            if site and len(not_checked["error_sites"]) < 120:
                not_checked["error_sites"].append(site)
        elif status in HIT:
            counts["checked"] += 1
            hit = {"site": str(r.get("site_name", ""))[:60],
                   "category": str(r.get("category", ""))[:30],
                   "url": str(r.get("url", ""))[:120]}
            details = _clean_extra(r.get("extra"))
            if details:
                hit["details"] = details
            avatar = _avatar(r.get("media"))
            if avatar:
                hit["avatar"] = avatar
            hits.append(hit)
        elif status in ABSENT:
            counts["checked"] += 1
            counts["absent"] += 1
    label = "registered" if kind == "email" else "possible_match"
    for h in hits:
        h["label"] = label
        h["source"] = SOURCE
    return {"hits": hits[:MAX_HITS], "hit_count": len(hits), **counts, **not_checked}


def _why(proc, value: str) -> str:
    """Last line of the scanner's own error output, with the scanned value removed, capped."""
    lines = [ln.strip() for ln in (getattr(proc, "stderr", "") or "").splitlines() if ln.strip()]
    if not lines:
        return f" (exit code {getattr(proc, 'returncode', '?')}, no error text)"
    return " (" + lines[-1].replace(value, "<value>")[:200] + ")"


def _run(flag: str, value: str, include_loud: bool) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.json")
        cmd = [sys.executable, "-m", "user_scanner", flag, value, "-f", "json", "-o", out]
        if include_loud:
            cmd.append("--allow-loud")
        # Windows consoles default to cp1252 and crash on the emoji user-scanner prints when piped.
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_S, check=False, env=env)
        if not os.path.exists(out):
            raise RuntimeError("user-scanner produced no JSON output" + _why(proc, value))
        with open(out, encoding="utf-8") as fh:
            rows = json.load(fh)
    if not isinstance(rows, list):
        raise RuntimeError("unexpected user-scanner output shape")
    return rows


def _installed() -> bool:
    import importlib.util
    return importlib.util.find_spec("user_scanner") is not None


def _scan(flag: str, value: str, kind: str, include_loud: bool) -> dict:
    try:
        if not _installed():
            return result("unavailable", source=SOURCE,
                          error="user-scanner is not installed (pip install user-scanner).")
        rows = _run(flag, value, include_loud)
    except subprocess.TimeoutExpired:
        return result("error", source=SOURCE, error=f"Timed out after {TIMEOUT_S}s.")
    except Exception as e:  # noqa: BLE001
        return result("error", source=SOURCE, error=f"{type(e).__name__}: {e}")
    data = parse_rows(rows, kind)
    if data["checked"] == 0:
        return result("error", data, SOURCE,
                      error="No site gave a usable answer (blocked, offline or rate limited).")
    notes = []
    if data["errors"]:
        notes.append(f"{data['errors']} sites errored or were blocked and are NOT counted as 'not found'.")
    if data["skipped"]:
        notes.append(f"{data['skipped']} sites skipped because checking them can trigger a "
                     "password-reset email to the target.")
    if kind == "username":
        notes.append("Username matches are possible matches only: the handle may belong to someone else.")
    else:
        notes.append("Absence on a site is not proof the email is unused there.")
    return result("ok", data, SOURCE, note=" ".join(notes))


def email_scan(email: str, include_loud: bool = False) -> dict:
    return _scan("-e", validate_email(email), "email", include_loud)


def username_scan(username: str) -> dict:
    return _scan("-u", validate_username(username), "username", False)
