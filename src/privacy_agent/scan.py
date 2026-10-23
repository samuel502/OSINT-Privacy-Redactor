"""No-LLM scan path used by the Gradio screen: validate, run the lookups, merge, render.

Plain Python. The agent is an optional extra; this path works with no API key.
Nothing here touches Gradio, so it can be tested offline.

Modes: "email" | "username" | "both".
Labels shown to the user: confirmed (the site itself reported the email), possible match
(a username hit, may belong to someone else). Anything that did not run is listed under
"Could not check", never shown as "nothing found".
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .merge import merge_findings, routes_by_domain
from .schema import validate_email
from .tools import dispatch
from .tools.userscan import validate_username

MODES = ("email", "username", "both")
PLAYBOOKS = Path(__file__).resolve().parent / "data" / "playbooks.json"


def validate_scan_inputs(mode: str, email: str, username: str, own: bool) -> tuple[str | None, str | None]:
    """Return (clean_email, clean_username). Raises ValueError with a message safe to show."""
    if mode not in MODES:
        raise ValueError("Choose a mode: email, username or both.")
    if not own:
        raise ValueError("Please tick the box to confirm this is your own email or username. "
                         "This tool is for checking yourself.")
    clean_email = clean_user = None
    if mode in ("email", "both"):
        clean_email = validate_email(email)
    if mode in ("username", "both"):
        if not (username or "").strip():
            raise ValueError("Please enter a username.")
        clean_user = validate_username(username)
    return clean_email, clean_user


def load_entries() -> list:
    return json.loads(PLAYBOOKS.read_text(encoding="utf-8"))


def load_routes() -> dict:
    return routes_by_domain(load_entries())


def run_scan(mode: str, email: str, username: str, own: bool, dispatch_fn=dispatch, routes=None):
    """Generator: {"type": "step", "text"} events, then one {"type": "bundle", "bundle"}."""
    clean_email, clean_user = validate_scan_inputs(mode, email, username, own)
    ctx = {"email": clean_email or "", "jurisdiction": "other"}
    email_res = breach_res = None
    user_res = []

    if clean_email:
        yield {"type": "step", "text": "Checking which services have an account for this email (about 30 seconds to a few minutes)..."}
        email_res = dispatch_fn("email_scan", {}, ctx)
        yield {"type": "step", "text": f"  -> email scan: {email_res['status']}"}
        yield {"type": "step", "text": "Checking known data breaches..."}
        breach_res = dispatch_fn("breach_lookup", {}, ctx)
        yield {"type": "step", "text": f"  -> breach check: {breach_res['status']}"}
    if clean_user:
        yield {"type": "step", "text": "Searching public profiles for the username (this can take a few minutes)..."}
        r = dispatch_fn("username_scan", {"username": clean_user}, ctx)
        user_res.append(r)
        yield {"type": "step", "text": f"  -> username scan: {r['status']}"}

    merged = merge_findings(email_scan=email_res, username_scans=user_res or None,
                            breach=breach_res, routes=routes if routes is not None else {})
    bundle = {"mode": mode, "merged": merged, "raw": {"email_scan": email_res, "breach": breach_res,
                                                     "username_scans": user_res}}
    bundle["report_md"] = render_exposure(merged, mode)
    yield {"type": "step", "text": "Report built."}
    yield {"type": "bundle", "bundle": bundle}


# ---------------------------------------------------------------- rendering

def _cell(s) -> str:
    return str(s or "").replace("|", "/").replace("\n", " ")[:90]


def render_exposure(merged: dict, mode: str = "both") -> str:
    s = merged["summary"]
    out = ["## What was found", "",
           f"Source: **live lookups** (user-scanner, XposedOrNot), run just now. "
           f"Confirmed accounts: **{s['confirmed']}**. Possible matches: **{s['possible']}**. "
           f"Breaches: **{s['breaches']}**."]
    if s["checks_failed"]:
        out += ["", "**Some checks did not run:** " + ", ".join(s["checks_failed"]) +
                ". See the list at the bottom. This is not the same as 'nothing found'."]

    confirmed = [a for a in merged["accounts"] if a["label"] == "confirmed"]
    possible = [a for a in merged["accounts"] if a["label"] == "possible_match"]
    if confirmed:
        out += ["", "### Confirmed accounts",
                "The site itself said this email is registered.", "",
                "| Site | Category | Details the site shows | Found by |", "| --- | --- | --- | --- |"]
        for a in confirmed:
            det = ", ".join(f"{k}: {v}" for k, v in a["details"].items())
            out.append(f"| {_cell(a['site'])} | {_cell(a.get('category', ''))} | {_cell(det)} | {_cell(', '.join(a['sources']))} |")
    elif "email accounts" in s["checks_ok"]:
        out += ["", "### Confirmed accounts", "None found among the sites that answered."]
    if possible:
        out += ["", "### Possible matches (username)",
                "These pages exist for that username. They may belong to someone else, so check each one.", "",
                "| Site | Link |", "| --- | --- |"]
        for a in possible:
            out.append(f"| {_cell(a['site'])} | {_cell(a['url'])} |")
    if merged["breaches"]:
        out += ["", "### Data breaches", ", ".join(merged["breaches"])]
    elif "breaches" in s["checks_ok"]:
        out += ["", "### Data breaches", "None found in this dataset. That is not proof the email was never exposed."]
    if merged["could_not_check"]:
        out += ["", "### Could not check", ""] + [f"- {n}" for n in merged["could_not_check"]]
    return "\n".join(out)


def _tier(e: dict) -> int:
    if e.get("opt_out_type") == "email" or e.get("opt_out_email"):
        return 3  # a written request, no form
    if e.get("needs_captcha"):
        return 2  # a bot check you click
    return 1      # form plus email link or code


TIER_NAMES = {1: "Easiest: a form, then an email link or code",
              2: "Needs a bot check that you click",
              3: "A written request by email"}


def render_optout(entries: list[dict]) -> str:
    """Opt-out routes for OSINT lookup sites, grouped by how much work they need."""
    sites = [e for e in entries if e.get("category") == "lookup_service"]
    if not sites:
        return "No OSINT-site routes are loaded."
    out = ["## Opt out of OSINT lookup sites", "",
           "These sites can profile an email or username. Each route below was researched from the site's own "
           "page or a guide. **Only entries marked verified have been tested.** Confirm the steps on the site.", ""]
    for tier in (1, 2, 3):
        group = sorted((e for e in sites if _tier(e) == tier), key=lambda e: e["name"].lower())
        if not group:
            continue
        out += [f"### {TIER_NAMES[tier]}", "", "| Site | Status | What to do |", "| --- | --- | --- |"]
        for e in group:
            status = "verified " + (e.get("last_verified") or "") if e.get("verified") else "researched, not tested"
            link = e.get("opt_out_url") or e.get("opt_out_email") or ""
            out.append(f"| [{_cell(e['name'])}]({link}) | {status} | {_cell(e.get('steps_summary'))} |" if link
                       else f"| {_cell(e['name'])} | {status} | {_cell(e.get('steps_summary'))} |")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- UI glue (no Gradio import)

UI_OUTPUTS = 5  # trace, report, opt-out checklist, erasure drafts, files


def write_files(bundle: dict) -> list:
    d = tempfile.mkdtemp(prefix="redactor-")
    md, js = os.path.join(d, "exposure-report.md"), os.path.join(d, "exposure-report.json")
    with open(md, "w", encoding="utf-8") as f:
        f.write(bundle["report_md"])
    with open(js, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in bundle.items() if k != "report_md"}, f, indent=2, default=str)
    return [md, js]


def ui_scan(mode, email, username, own, dispatch_fn=dispatch, entries=None, routes=None):
    """Yields 5-tuples: (trace, report, checklist, drafts, files)."""
    entries = load_entries() if entries is None else entries
    routes = load_routes() if routes is None else routes
    trace = []
    try:
        for ev in run_scan(mode, email, username, own, dispatch_fn=dispatch_fn, routes=routes):
            if ev["type"] == "step":
                trace.append("- " + ev["text"])
                yield ("\n".join(trace), "", "", "", None)
            else:
                b = ev["bundle"]
                yield ("\n".join(trace), b["report_md"], render_optout(entries), "", write_files(b))
    except ValueError as e:
        yield (f"**Error:** {e}", "", "", "", None)
