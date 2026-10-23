"""No-LLM scan path used by the Gradio screen: validate, run the lookups, merge, render.

Plain Python. The agent is an optional extra; this path works with no API key.
Nothing here touches Gradio, so it can be tested offline.

Modes: "email" | "username" | "both".
Labels shown to the user: confirmed (the site itself reported the email), possible match
(a username hit, may belong to someone else). Anything that did not run is listed under
"Could not check", never shown as "nothing found".
"""
from __future__ import annotations

import html
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

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
    bundle["report_html"] = render_cards_html(merged)
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


# ---------------------------------------------------------------- card layout (HTML)
# Every value from a third-party site is escaped and capped. Links and images must be https.

CSS = """<style>
.xp{--b:rgba(128,128,128,.35);--bg:rgba(128,128,128,.10);font-size:15px;line-height:1.45}
.xp h3{margin:18px 0 8px}.xp .sub{opacity:.75;margin:0 0 10px}
.xp .sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin:10px 0}
.xp .box,.xp .card{border:1px solid var(--b);background:var(--bg);border-radius:12px;padding:12px 14px}
.xp .box b{display:block;font-size:12px;letter-spacing:.04em;text-transform:uppercase;opacity:.7;margin-bottom:6px}
.xp .chip{display:inline-block;border:1px solid var(--b);border-radius:999px;padding:2px 10px;margin:2px 4px 2px 0;font-size:13px}
.xp .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.xp .head{display:flex;gap:10px;align-items:center;margin-bottom:6px}
.xp .av{width:44px;height:44px;border-radius:50%;object-fit:cover;flex:none}
.xp .ini{width:44px;height:44px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-weight:700;border:1px solid var(--b)}
.xp .nm{font-weight:700}.xp .cat{font-size:12px;opacity:.7}
.xp dl{margin:6px 0 0;display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:13px}
.xp dt{opacity:.65}.xp dd{margin:0;word-break:break-word}
.xp .foot{margin-top:8px;font-size:13px}.xp .tag{font-size:12px;opacity:.7}
.xp .warn{border:1px solid #d9a400;background:rgba(217,164,0,.12);border-radius:10px;padding:10px 12px;margin:10px 0}
.xp .pics{display:flex;flex-wrap:wrap;gap:6px}.xp .pics img{width:44px;height:44px;border-radius:50%;object-fit:cover}
</style>"""

DETAIL_LABELS = {"name": "Name", "username": "Username", "joined": "Joined", "created": "Created",
                 "last_profile_update": "Profile updated", "last_active": "Last active",
                 "last_seen": "Last seen", "location": "Location", "followers": "Followers",
                 "following": "Following"}


def _e(x, n=120) -> str:
    return html.escape(str(x or "")[:n], quote=True)


def _https(u: str) -> str:
    try:
        return u if u and urlsplit(u).scheme == "https" and len(u) <= 300 else ""
    except ValueError:
        return ""


def _link(url: str, text: str) -> str:
    u = _https(url) or (url if url.startswith("http://") and len(url) <= 300 else "")
    return f'<a href="{_e(u, 300)}" target="_blank" rel="noopener noreferrer nofollow">{_e(text)}</a>' if u else ""


def html_notice(title: str, body: str = "") -> str:
    return f'{CSS}<div class="xp"><div class="warn"><b>{_e(title, 200)}</b><br>{_e(body, 600)}</div></div>'


def _card(a: dict) -> str:
    name = _e(a["site"], 60)
    av = _https(a.get("avatar", ""))
    pic = (f'<img class="av" src="{_e(av, 300)}" alt="" loading="lazy" referrerpolicy="no-referrer">' if av
           else f'<div class="ini">{_e((a["site"] or "?")[:1].upper(), 2)}</div>')
    cat = f'<div class="cat">{_e(a.get("category", ""), 30)}</div>' if a.get("category") else ""
    rows = "".join(f"<dt>{_e(DETAIL_LABELS.get(k, k), 30)}</dt><dd>{_e(v, 80)}</dd>"
                   for k, v in a["details"].items())
    if a["label"] == "confirmed":
        tag, link = "confirmed: the site reported this email", _link(a["url"], "Open site (login page, not your profile)")
    else:
        tag, link = "possible match: may be someone else", _link(a["url"], "Open profile page")
    rem = a.get("removal", {})
    rm = ""
    if rem.get("status") in ("verified", "unverified") and rem.get("url"):
        rm = f' &middot; {_link(rem["url"], "Removal route (" + ("verified" if rem["status"] == "verified" else "researched, not tested") + ")")}'
    return (f'<div class="card"><div class="head">{pic}<div><div class="nm">{name}</div>{cat}</div></div>'
            f'<div class="tag">{_e(tag)}</div>{"<dl>" + rows + "</dl>" if rows else ""}'
            f'<div class="foot">{link}{rm}</div></div>')


def _chips(values) -> str:
    return "".join(f'<span class="chip">{_e(v, 60)}</span>' for v in values) or '<span class="tag">none reported</span>'


def render_cards_html(merged: dict) -> str:
    s = merged["summary"]
    accounts = merged["accounts"]
    names, users, pics = [], [], []
    for a in accounts:
        for k, bucket in (("name", names), ("username", users)):
            v = a["details"].get(k)
            if v and v not in bucket:
                bucket.append(v)
        av = _https(a.get("avatar", ""))
        if av and av not in pics:
            pics.append(av)
    out = [CSS, '<div class="xp">']
    out.append(f'<h3>What was found</h3><p class="sub">Live lookups (user-scanner, XposedOrNot), run just now. '
               f'<b>{s["confirmed"]}</b> confirmed accounts, <b>{s["possible"]}</b> possible matches, '
               f'<b>{s["breaches"]}</b> breaches.</p>')
    if s["checks_failed"]:
        out.append('<div class="warn"><b>Some checks did not run:</b> ' + _e(", ".join(s["checks_failed"]), 200) +
                   '. This is not the same as "nothing found". Details at the bottom.</div>')
    out.append('<div class="sum">'
               f'<div class="box"><b>Names shown by sites</b>{_chips(names)}</div>'
               f'<div class="box"><b>Usernames</b>{_chips(users)}</div>'
               '<div class="box"><b>Profile pictures</b><div class="pics">' +
               "".join(f'<img src="{_e(u, 300)}" alt="" loading="lazy" referrerpolicy="no-referrer">' for u in pics) +
               ("" if pics else '<span class="tag">none reported</span>') +
               '</div><div class="tag">Loaded straight from each site by your browser.</div></div>'
               f'<div class="box"><b>Data breaches</b>{_chips(merged["breaches"])}</div></div>')
    for label, title, sub in (("confirmed", "Confirmed accounts", "The site itself said this email is registered."),
                              ("possible_match", "Possible matches (username)",
                               "These pages exist for that username. They may belong to someone else.")):
        group = [a for a in accounts if a["label"] == label]
        if group:
            out.append(f'<h3>{title} ({len(group)})</h3><p class="sub">{sub}</p><div class="grid">' +
                       "".join(_card(a) for a in group) + "</div>")
    if not accounts and not s["checks_failed"]:
        out.append('<p class="sub">No accounts found among the sites that answered. '
                   'That is not proof none exist.</p>')
    if merged["could_not_check"]:
        out.append('<h3>Could not check</h3><ul>' + "".join(f"<li>{_e(n, 300)}</li>" for n in merged["could_not_check"]) + "</ul>")
    out.append("</div>")
    return "".join(out)


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
        json.dump({k: v for k, v in bundle.items() if k not in ("report_md", "report_html")}, f, indent=2, default=str)
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
                t = "\n".join(trace)
                yield (t, html_notice("Scan running... please wait", "This can take a few minutes. Keep this page and the terminal open."), "", "", None)
            else:
                b = ev["bundle"]
                yield ("\n".join(trace), b["report_html"], render_optout(entries), "", write_files(b))
    except ValueError as e:
        yield (f"### Cannot start the scan\n\n**{e}**", html_notice("Cannot start the scan", str(e)), "", "", None)
