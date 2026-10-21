"""Tool 1 (discovery): which services have an account registered to this email?

Uses holehe (probes sign-up / password-reset flows) plus a Gravatar check.
holehe marks every site as  [+] registered,  [-] not registered,  [x] rate-limited (NOT checked).
We report confirmed accounts AND the rate-limited sites separately, so "not checked" is never
mistaken for "no account". No guessed or default entries.
"""
from __future__ import annotations

import csv
import glob
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

from ..schema import result, validate_email

HOLEHE_TIMEOUT = 150  # seconds

# "[+] domain.tld [optional hints]", "[-] domain.tld", "[x] domain.tld"
_LINE = re.compile(r"^\[(?P<s>[+\-x])\]\s+(?P<d>[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})(?:\s+(?P<extra>.+))?$")


def parse_holehe_text(text: str):
    """Return (confirmed, rate_limited, not_registered_count) from holehe's console output."""
    confirmed, limited, absent = set(), set(), set()
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue  # legend, banner, and summary lines don't match
        domain, status = m["d"].lower(), m["s"]
        if status == "+":
            confirmed.add(domain)
        elif status == "x":
            limited.add(domain)
        else:
            absent.add(domain)
    return sorted(confirmed), sorted(limited), len(absent)


def parse_holehe_csv_extras(path: str) -> dict:
    """Best-effort: masked recovery email / phone / other hints for registered sites.
    Header matching is case-insensitive. Never raises on odd files (caller wraps in try)."""
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if r.get("exists", "").lower() != "true":
                continue
            domain = (r.get("domain") or r.get("name") or "").lower()
            hints = {k: v for k, v in {
                "email_recovery": r.get("email recovery", ""),
                "phone_number": r.get("phone number", ""),
                "others": r.get("others", "")}.items() if v and v.lower() not in {"none", "false"}}
            if domain and hints:
                out[domain] = hints
    return out


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


def _run_holehe(holehe: str, email: str, tmp: str, with_csv: bool):
    cmd = [holehe, "--no-color", "--no-clear"] + (["-C"] if with_csv else []) + [email]
    return subprocess.run(cmd, cwd=tmp, capture_output=True, text=True, timeout=HOLEHE_TIMEOUT)


def footprint_probe(email: str) -> dict:
    email = validate_email(email)
    sources, confirmed, limited, absent, extras = {}, set(), [], 0, {}

    holehe = shutil.which("holehe")
    if not holehe:
        sources["holehe"] = "missing (pip install holehe)"
    else:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                proc = _run_holehe(holehe, email, tmp, with_csv=True)
                found, lim, absent_n = parse_holehe_text(proc.stdout)
                if not (found or lim or absent_n) and proc.returncode != 0:
                    proc = _run_holehe(holehe, email, tmp, with_csv=False)  # in case -C is unsupported
                    found, lim, absent_n = parse_holehe_text(proc.stdout)
                if not (found or lim or absent_n):
                    detail = (proc.stderr or proc.stdout or "no output").strip()[:200]
                    sources["holehe"] = f"error: no results parsed ({detail})"
                else:
                    sources["holehe"] = "ok"
                    confirmed.update(found)
                    limited, absent = lim, absent_n
                    for path in glob.glob(os.path.join(tmp, "*.csv")):
                        try:
                            extras = parse_holehe_csv_extras(path)
                        except Exception:  # noqa: BLE001
                            extras = {}
                        break
            except subprocess.TimeoutExpired as e:
                partial = e.stdout or b""
                if isinstance(partial, bytes):
                    partial = partial.decode("utf-8", "replace")
                found, lim, absent_n = parse_holehe_text(partial)
                if found or lim or absent_n:
                    confirmed.update(found)
                    limited, absent = lim, absent_n
                    sources["holehe"] = f"ok (partial: killed at {HOLEHE_TIMEOUT}s)"
                else:
                    sources["holehe"] = f"error: timed out after {HOLEHE_TIMEOUT}s, nothing parsed"
            except Exception as e:  # noqa: BLE001
                sources["holehe"] = f"error: {e}"

    grav = _gravatar(email)
    sources["gravatar"] = {True: "found", False: "not_found", None: "unknown"}[grav]
    if grav:
        confirmed.add("gravatar.com")

    if sources["holehe"] != "ok" and grav is None:
        return result("unavailable", {"sources": sources}, "holehe+gravatar",
                      error="No footprint source could run.")

    checked = len(confirmed - {"gravatar.com"}) + len(limited) + absent
    note = "Only confirmed registrations are listed. Absence is NOT proof an account doesn't exist."
    if limited:
        note += (f" {len(limited)} of {checked} sites were rate-limited and NOT checked; "
                 "those may hold accounts. Re-run later or from a different network (VPN/shared IPs trigger this).")
    return result(
        "ok",
        {"confirmed_accounts": sorted(confirmed),
         "rate_limited_or_unchecked": limited,
         "coverage": "partial" if limited else "full",
         "holehe_counts": {"registered": len(confirmed - {"gravatar.com"}),
                           "not_registered": absent, "rate_limited": len(limited)},
         "account_hints": {d: h for d, h in extras.items() if d in confirmed},
         "sources": sources},
        "holehe+gravatar", note=note)
