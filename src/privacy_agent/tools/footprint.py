"""Tool 1 (discovery): which services have an account registered to this email?

Uses holehe (probes password-reset style flows) plus a Gravatar check.
Only reports accounts a source actually confirmed. No guessed or default entries.
"""
from __future__ import annotations

import csv
import glob
import hashlib
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

from ..schema import result, validate_email

HOLEHE_TIMEOUT = 150  # seconds; holehe checks ~120 sites and can be slow


def parse_holehe_csv(path: str):
    confirmed, limited = set(), set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = (row.get("Domain") or row.get("domain") or row.get("Name") or "").strip().lower()
            if not domain:
                continue
            if str(row.get("Rate Limit", "")).strip().lower() == "true":
                limited.add(domain)
            elif str(row.get("Exists", "")).strip().lower() == "true":
                confirmed.add(domain)
    return sorted(confirmed), sorted(limited)


def parse_holehe_text(text: str):
    confirmed = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[+]"):
            tokens = line[3:].strip().split()
            if tokens and "." in tokens[0]:
                confirmed.add(tokens[0].lower())
    return sorted(confirmed), []


def _gravatar(email: str):
    """True = profile exists, False = confirmed absent, None = could not tell."""
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()  # Gravatar's scheme
    req = urllib.request.Request(f"https://www.gravatar.com/{digest}.json",
                                 headers={"User-Agent": "privacy-agent/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return True if resp.status == 200 else None
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def footprint_probe(email: str) -> dict:
    email = validate_email(email)
    sources, confirmed, limited = {}, set(), []

    holehe = shutil.which("holehe")
    if not holehe:
        sources["holehe"] = "missing (pip install holehe)"
    else:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                proc = subprocess.run(
                    [holehe, "--only-used", "--no-color", "--no-clear", "-C", email],
                    cwd=tmp, capture_output=True, text=True, timeout=HOLEHE_TIMEOUT)
                csvs = glob.glob(os.path.join(tmp, "*.csv"))
                found, lim = parse_holehe_csv(csvs[0]) if csvs else parse_holehe_text(proc.stdout)
                if proc.returncode != 0 and not found and not csvs:
                    sources["holehe"] = f"error: {(proc.stderr or proc.stdout)[:200].strip()}"
                else:
                    sources["holehe"] = "ok"
                    confirmed.update(found)
                    limited = lim
            except subprocess.TimeoutExpired:
                sources["holehe"] = f"error: timed out after {HOLEHE_TIMEOUT}s"
            except Exception as e:  # noqa: BLE001
                sources["holehe"] = f"error: {e}"

    grav = _gravatar(email)
    sources["gravatar"] = {True: "found", False: "not_found", None: "unknown"}[grav]
    if grav:
        confirmed.add("gravatar.com")

    if sources["holehe"] != "ok" and grav is None:
        return result("unavailable", {"sources": sources}, "holehe+gravatar",
                      error="No footprint source could run.")
    return result(
        "ok",
        {"confirmed_accounts": sorted(confirmed),
         "rate_limited_or_unchecked": limited,
         "sources": sources},
        "holehe+gravatar",
        note="Only confirmed registrations are listed. Absence is NOT proof an account doesn't exist.")
