"""Deterministic audit pipeline. No LLM, no API key.

Used by `cli.py` (default mode) and the Gradio "Audit (no LLM key needed)" button, so the
tool is fully useful without a Groq/Gemini key. The agent is an enhancement, not a dependency.
"""
from __future__ import annotations

from .report import build_checklist, build_report
from .schema import validate_email
from .tools import dispatch
from .tools.playbooks import lookup_many

# The lookup sites that can answer for your address whether or not you have a visible account.
# Entries missing from playbooks.json are reported as "unrouted" instead of being skipped silently.
LOOKUP_TARGETS = [
    "emailosint.org", "fingerprint.to", "osintleak.com", "epieos.com",
    "haveibeenpwned.com", "leakcheck.io", "hunter.io", "signalhire.com",
    "rocketreach.co", "apollo.io", "lusha.com", "snov.io", "contactout.com",
    "zoominfo.com", "fingerprint.com",
]


def run_pipeline(email: str, jurisdiction: str = "gdpr", full_name: str | None = None):
    """Generator: {"type": "step"} events, then one {"type": "bundle"}."""
    email = validate_email(email)
    ctx = {"email": email, "jurisdiction": jurisdiction, "full_name": full_name}

    yield {"type": "step", "text": "Probing services for an account (holehe + Gravatar, up to ~5 min)..."}
    footprint = dispatch("footprint_probe", {}, ctx)
    yield {"type": "step", "text": f"  -> account probe: {footprint['status']}"}

    yield {"type": "step", "text": "Checking known breaches (XposedOrNot)..."}
    breaches = dispatch("breach_lookup", {}, ctx)
    yield {"type": "step", "text": f"  -> breach check: {breaches['status']}"}

    accounts = (footprint.get("data", {}).get("confirmed_accounts", [])
                if footprint.get("status") == "ok" else [])
    targets = sorted(set(accounts) | set(LOOKUP_TARGETS))
    yield {"type": "step", "text": f"Resolving opt-out routes for {len(targets)} services..."}
    routes = lookup_many(targets)
    unrouted = [d for d in targets if not routes.get(d)]
    if unrouted:
        yield {"type": "step", "text": f"  -> {len(unrouted)} have no registry entry yet"}

    yield {"type": "step", "text": "Drafting erasure requests for services with no route..."}
    drafts = []
    for d in accounts:
        if not routes.get(d):
            dr = dispatch("draft_erasure_request", {"platform_domain": d}, ctx)
            if dr.get("status") == "ok":
                drafts.append(dr["data"])

    checklist = build_checklist(footprint, breaches, routes)
    lookup_entries = [e for d in LOOKUP_TARGETS for e in (routes.get(d) or [])]
    playbook_map = {d: {"data": {"matches": routes[d]}} for d in accounts if routes.get(d)}

    bundle = {
        "email": email, "jurisdiction": jurisdiction, "full_name": full_name,
        "footprint": footprint, "breaches": breaches, "routes": routes,
        "drafts": drafts, "checklist": checklist, "unrouted": unrouted,
    }
    bundle["report_md"] = build_report(footprint, breaches, playbook_map, lookup_entries,
                                       drafts=drafts, checklist=checklist, email=email)
    yield {"type": "step", "text": "Report built."}
    yield {"type": "bundle", "bundle": bundle}
