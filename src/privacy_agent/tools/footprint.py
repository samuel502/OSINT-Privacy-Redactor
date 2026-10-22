"""Tool 1 (discovery): which services have an account registered to this email?

holehe probes sign-up / password-reset flows; a Gravatar check covers the one profile service
that answers by hash. Optionally a second source (fingerprint.to, `deep=True`) resolves 200+
platforms in a browser and returns the profile fields behind each match.

holehe runs through tools/_holehe_runner.py, a subprocess, because:

  * holehe's own CLI builds its httpx client with follow_redirects left at the default (False).
    Any site that has since moved host answers 3xx with an empty body, the module crashes on
    the parse, and holehe reports the crash as "[x] rate limit". Measured on the project
    author's own address: 118 of 121 sites "rate limited" via the CLI, 65 via this runner.
  * it also keeps holehe (GPLv3) on the far side of a process boundary, and hands back typed
    records instead of console text to regex.

holehe resolves each site as exists / not-registered / unresolved. Unresolved means NOT
checked (throttled or the module failed) and is reported separately, so "couldn't check" is
never read as "no account". Nothing is guessed or padded.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..schema import result, validate_email

try:
    from .fingerprint_to import fingerprint_probe as _fingerprint_probe
except ImportError:                     # optional second source, added separately
    _fingerprint_probe = None

RUNNER = Path(__file__).with_name("_holehe_runner.py")
RUNNER_TIMEOUT = int(os.environ.get("HOLEHE_RUNNER_TIMEOUT", "300"))
MAX_PASSES = int(os.environ.get("HOLEHE_MAX_PASSES", "2"))
PASS_PAUSE_S = int(os.environ.get("HOLEHE_PASS_PAUSE", "8"))


def _run_runner(email: str) -> list:
    """One full holehe sweep. Raises on failure."""
    proc = subprocess.run([sys.executable, str(RUNNER), email],
                          capture_output=True, text=True, timeout=RUNNER_TIMEOUT)
    lines = (proc.stdout or "").strip().splitlines()
    if not lines:
        raise RuntimeError((proc.stderr or "no output").strip()[:300])
    payload = json.loads(lines[-1])
    if not payload.get("ok"):
        raise RuntimeError(str(payload.get("error"))[:300])
    return payload["records"]


def _classify(records):
    """Split records into (confirmed, unresolved, absent, errored, hints)."""
    confirmed, unresolved, absent, errored, hints = set(), set(), set(), set(), {}
    for r in records:
        d = (r.get("domain") or r.get("name") or "").strip().lower()
        if not d:
            continue
        if r.get("error"):
            errored.add(d)
        elif r.get("exists"):
            confirmed.add(d)
        elif r.get("rateLimit"):
            unresolved.add(d)
        else:
            absent.add(d)
        if r.get("exists"):
            extra = {k: v for k, v in {"email_recovery": r.get("emailrecovery"),
                                       "phone_number": r.get("phoneNumber"),
                                       "others": r.get("others")}.items() if v}
            if extra:
                hints[d] = extra
    return confirmed, unresolved, absent, errored, hints


def merge_passes(passes):
    """passes: list of (confirmed, unresolved, absent) sets.
    A confirmed hit beats a definite miss, which beats 'never resolved'."""
    confirmed, unresolved, absent = set(), set(), set()
    for c, u, a in passes:
        confirmed |= c
        unresolved |= u
        absent |= a
    unresolved -= confirmed
    unresolved -= absent
    absent -= confirmed
    return confirmed, unresolved, absent


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
    except Exception:  # noqa: BLE001
        return None


def footprint_probe(email: str, retry_blocked: bool = True, deep: bool = False) -> dict:
    """Probe for accounts.

    retry_blocked: a sweep is ~5s, so a second pass to recover unresolved sites is cheap.
    deep:          also run the fingerprint.to second source (needs playwright; ~2-3 min).
    """
    email = validate_email(email)
    sources, hints = {}, {}
    confirmed, limited_domains, absent, errored = set(), set(), set(), set()
    holehe_ok, total_sites = False, 0

    if not RUNNER.exists():
        sources["holehe"] = f"missing {RUNNER.name}"
    else:
        passes, last_error = [], None
        for attempt in range(max(1, MAX_PASSES) if retry_blocked else 1):
            if attempt:
                time.sleep(PASS_PAUSE_S)
            try:
                records = _run_runner(email)
                if not records:
                    raise RuntimeError("runner returned no records")
            except Exception as e:  # noqa: BLE001
                last_error = f"error: {e}"
                break
            c, u, a, er, h = _classify(records)
            passes.append((c, u, a))
            total_sites = max(total_sites, len(records))
            errored |= er
            hints.update({k: v for k, v in h.items() if k not in hints})
            if not u:
                break                      # nothing unresolved, no reason for another pass
        if passes:
            confirmed, limited_domains, absent = merge_passes(passes)
            holehe_ok = True
            suffix = "" if len(passes) == 1 else f", {len(passes)} passes"
            sources["holehe"] = f"ok ({total_sites} sites{suffix})"
        else:
            sources["holehe"] = last_error or "error: no results"

    profiles = []
    if deep:
        if _fingerprint_probe is None:
            sources["fingerprint.to"] = "missing module (tools/fingerprint_to.py)"
        else:
            fp = _fingerprint_probe(email)
            if fp.get("status") == "ok":
                profiles = fp["data"]["profiles"]
                confirmed |= set(fp["data"]["domains"])
                sources["fingerprint.to"] = f"ok ({len(profiles)} profiles)"
            else:
                sources["fingerprint.to"] = fp.get("error") or "unavailable"

    grav = _gravatar(email)
    sources["gravatar"] = {True: "found", False: "not_found", None: "unknown"}[grav]
    if grav:
        confirmed.add("gravatar.com")

    if not holehe_ok and grav is None and not profiles:
        return result("unavailable", {"sources": sources}, "holehe+gravatar",
                      error="No footprint source could run.")

    checked = len(confirmed - {"gravatar.com"}) + len(limited_domains) + len(absent)
    note = "Only confirmed registrations are listed. Absence is NOT proof an account doesn't exist."
    if limited_domains:
        note += (f" {len(limited_domains)} of {checked} sites did not resolve (throttled or the "
                 "checker failed) and were NOT checked; those may hold accounts.")
    if errored:
        note += f" {len(errored)} site(s) errored and are not counted as checked."
    if profiles:
        note += f" {len(profiles)} profiles were read from fingerprint.to (second source)."
    return result(
        "ok",
        {"confirmed_accounts": sorted(confirmed),
         "rate_limited_or_unchecked": sorted(limited_domains),
         "errored": sorted(errored),
         "profiles": profiles,
         "coverage": "partial" if limited_domains else "full",
         "holehe_counts": {"registered": len(confirmed - {"gravatar.com"}),
                           "not_registered": len(absent),
                           "rate_limited": len(limited_domains)},
         "account_hints": {d: h for d, h in hints.items() if d in confirmed},
         "sources": sources},
        "holehe+gravatar", note=note)
