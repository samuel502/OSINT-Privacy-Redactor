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


def validate_scan_inputs(mode: str, email: str, username: str) -> tuple[str | None, str | None]:
    """Return (clean_email, clean_username). Raises ValueError with a message safe to show."""
    if mode not in MODES:
        raise ValueError("Choose a mode: email, username or both.")
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


MAX_PIVOT = 3


def looks_generated(u: str) -> bool:
    """Auto-generated handles (e.g. random letters) match nobody else, so searching them is wasted time."""
    letters = [c for c in u.lower() if c.isalpha()]
    return len(letters) >= 10 and sum(c in "aeiou" for c in letters) / len(letters) < 0.2


def pivot_usernames(email_res: dict | None, already: list | None = None, limit: int = MAX_PIVOT,
                    profiles_res: dict | None = None) -> list:
    """Usernames sites or public profiles reported for the email: valid, de-duplicated, capped.

    Public-profile handles come first (the owner published them). Random-looking handles are skipped.
    """
    seen = {u.lower() for u in (already or [])}
    cands = []
    for p in ((profiles_res or {}).get("data") or {}).get("profiles", []):
        cands.append((p.get("details") or {}).get("username"))
    for h in ((email_res or {}).get("data") or {}).get("hits", []):
        cands.append((h.get("details") or {}).get("username"))
    out = []
    for u in cands:
        if not u:
            continue
        try:
            u = validate_username(u)
        except ValueError:
            continue
        if u.lower() in seen or looks_generated(u):
            continue
        seen.add(u.lower())
        out.append(u)
    return out[:limit]


def run_scan(mode: str, email: str, username: str, dispatch_fn=dispatch, routes=None, pivot: bool = False):
    """Generator: {"type": "step", "text"} events, then one {"type": "bundle", "bundle"}."""
    clean_email, clean_user = validate_scan_inputs(mode, email, username)
    ctx = {"email": clean_email or "", "jurisdiction": "other"}
    email_res = breach_res = profiles_res = None
    user_res = []

    if clean_email:
        yield {"type": "step", "text": "Checking which services have an account for this email (about 30 seconds to a few minutes)..."}
        email_res = dispatch_fn("email_scan", {}, ctx)
        yield {"type": "step", "text": f"  -> email scan: {email_res['status']}"}
        yield {"type": "step", "text": "Looking for public profiles you published (Gravatar, GitHub)..."}
        profiles_res = dispatch_fn("public_profiles", {}, ctx)
        yield {"type": "step", "text": f"  -> public profiles: {profiles_res['status']}"}
        yield {"type": "step", "text": "Checking known data breaches..."}
        breach_res = dispatch_fn("breach_lookup", {}, ctx)
        yield {"type": "step", "text": f"  -> breach check: {breach_res['status']}"}
    if clean_user:
        yield {"type": "step", "text": "Searching public profiles for the username (this can take a few minutes)..."}
        r = dispatch_fn("username_scan", {"username": clean_user}, ctx)
        user_res.append(r)
        yield {"type": "step", "text": f"  -> username scan: {r['status']}"}

    if pivot and clean_email and (email_res or profiles_res):
        for u in pivot_usernames(email_res, [clean_user] if clean_user else [], profiles_res=profiles_res):
            yield {"type": "step", "text": f"Searching profile pages for a username the sites reported ({u}); this takes a few minutes..."}
            r = dispatch_fn("username_scan", {"username": u}, ctx)
            user_res.append(r)
            yield {"type": "step", "text": f"  -> username scan for {u}: {r['status']}"}

    merged = merge_findings(email_scan=email_res, username_scans=user_res or None,
                            breach=breach_res, routes=routes if routes is not None else {}, profiles=profiles_res)
    bundle = {"mode": mode, "merged": merged, "raw": {"email_scan": email_res, "breach": breach_res, "public_profiles": profiles_res,
                                                     "username_scans": user_res}}
    bundle["report_md"] = render_exposure(merged, mode)
    bundle["report_html"] = render_cards_html(merged)
    yield {"type": "step", "text": "Report built."}
    yield {"type": "bundle", "bundle": bundle}


# ---------------------------------------------------------------- rendering

def _cell(s, n: int = 90) -> str:
    return str(s or "").replace("|", "/").replace("\n", " ")[:n]


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
                "The site said this email is registered, or a public profile is tied to it.", "",
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
.xp .avw{position:relative;width:44px;height:44px;flex:none}
.xp .av{position:absolute;inset:0;width:44px;height:44px;border-radius:50%;object-fit:cover}
.xp .ini{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700}
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
                 "following": "Following", "has_public_page": "Public profile page"}


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
    hue = sum(map(ord, a["site"] or "?")) * 37 % 360
    img = (f'<img class="av" src="{_e(av, 300)}" alt="" loading="lazy" referrerpolicy="no-referrer" '
           f'onerror="this.remove()">' if av else "")
    pic = (f'<div class="avw"><div class="ini" style="background:hsl({hue} 55% 42%);color:#fff">'
           f'{_e((a["site"] or "?")[:1].upper(), 2)}</div>{img}</div>')
    cat = f'<div class="cat">{_e(a.get("category", ""), 30)}</div>' if a.get("category") else ""
    status = ("Registered with your email" if "email_registered" in a["evidence"] else
              "Public profile for your email" if "public_profile" in a["evidence"] else
              "Listed on a public profile" if a.get("listed_by") else "Username page exists (possible match)")
    rows = f"<dt>Account</dt><dd>{_e(status, 60)}</dd>" + "".join(
        f"<dt>{_e(DETAIL_LABELS.get(k, k), 30)}</dt><dd>{_e(v, 80)}</dd>" for k, v in a["details"].items())
    if a["label"] == "confirmed" and "public_profile" in a["evidence"]:
        tag = a.get("note") or "confirmed: public profile tied to this email"
        link = _link(a.get("profile_url") or a["url"], "Open profile page")
    elif a["label"] == "confirmed" and a.get("profile_url"):
        tag = "confirmed by email; profile page found by username (check it is yours)"
        link = _link(a["profile_url"], "Open profile page")
    elif a["label"] == "confirmed":
        tag, link = "confirmed: the site reported this email", _link(a["url"], "Open site (login page, not your profile)")
    elif a.get("listed_by"):
        tag = f"listed by the owner on the {a['listed_by'].capitalize()} profile for this email"
        link = _link(a["url"], "Open profile page")
    else:
        tag, link = "possible match: may be someone else", _link(a["url"], "Open profile page")
    rem = a.get("removal", {})
    rm = ""
    if rem.get("status") in ("verified", "unverified") and rem.get("url"):
        rm = f' &middot; {_link(rem["url"], "Removal route (" + ("verified" if rem["status"] == "verified" else "researched, not tested") + ")")}'
    return (f'<div class="card"><div class="head">{pic}<div><div class="nm">{name}</div>{cat}</div></div>'
            f'<div class="tag">{_e(tag)}</div><dl>{rows}</dl>'
            f'<div class="foot">{link}{rm}</div></div>')


def _chips(values) -> str:
    return "".join(f'<span class="chip">{_e(v, 60)}</span>' for v in values) or '<span class="tag">none reported</span>'


def _date(v: str):
    from datetime import date
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def _date_range(accounts: list):
    """Earliest 'joined/created' and latest 'last_*/updated' date any site reported. None if none did."""
    joined = [d for a in accounts for k in ("joined", "created") if (d := _date(a["details"].get(k)))]
    last = [d for a in accounts for k in ("last_active", "last_seen", "last_profile_update")
            if (d := _date(a["details"].get(k)))]
    return (min(joined) if joined else None), (max(last) if last else None)


def _profile_links(accounts: list) -> list:
    out = []
    for a in accounts:
        u = a.get("profile_url") or (a["url"] if a["label"] == "possible_match" else "")
        if u and _link(u, "x"):
            out.append((a["site"], u))
    return out


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
    first, last = _date_range(accounts)
    plinks = _profile_links(accounts)
    out.append('<div class="sum">'
               f'<div class="box"><b>Accounts</b><span style="font-size:26px;font-weight:700">{len(accounts)}</span>'
               f'<div class="tag">{s["confirmed"]} confirmed, {s["possible"]} possible</div></div>'
               f'<div class="box"><b>Earliest join date reported</b>{_e(first.isoformat() if first else "not reported by any site", 40)}</div>'
               f'<div class="box"><b>Newest date any site reported</b>{_e(last.isoformat() if last else "not reported by any site", 40)}<div class="tag">Sites report different things (profile update, last active). Real activity may be newer.</div></div>'
               '</div>')
    out.append('<div class="sum">'
               f'<div class="box"><b>Names shown by sites</b>{_chips(names)}</div>'
               f'<div class="box"><b>Usernames</b>{_chips(users)}</div>'
               '<div class="box"><b>Profile pictures</b><div class="pics">' +
               "".join(f'<img src="{_e(u, 300)}" alt="" loading="lazy" referrerpolicy="no-referrer">' for u in pics) +
               ("" if pics else '<span class="tag">none reported</span>') +
               '</div><div class="tag">Loaded straight from each site by your browser.</div></div>'
               f'<div class="box"><b>Data breaches</b>{_chips(merged["breaches"])}</div>'
               '<div class="box"><b>Profile links</b>' +
               ("".join(f'<div>{_link(u, n + " \u2197")}</div>' for n, u in plinks) or '<span class="tag">none found</span>') +
               '</div></div>')
    for label, title, sub in (("confirmed", "Confirmed accounts", "The site said this email is registered, or a public profile is tied to it."),
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
        nc = merged.get("not_checked") or {}
        for key, title in (("email_errors", "Sites that errored or blocked the check"),
                           ("email_skipped", "Sites skipped to avoid sending a password-reset email")):
            if nc.get(key):
                out.append(f'<details><summary>{_e(title)} ({len(nc[key])})</summary><div>' +
                           "".join(f'<span class="chip">{_e(n, 40)}</span>' for n in nc[key]) + "</div></details>")
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
            out.append(f"| [{_cell(e['name'])}]({link}) | {status} | {_cell(e.get('steps_summary'), 500)} |" if link
                       else f"| {_cell(e['name'])} | {status} | {_cell(e.get('steps_summary'), 500)} |")
        out.append("")
    return "\n".join(out)


OPTOUT_CSS = CSS.replace("</style>", """
.xp .chip.ok{border-color:#2e9e5b}.xp .chip.todo{border-color:#d9a400}
.xp details{margin-top:8px;font-size:13px}.xp pre{white-space:pre-wrap;margin:6px 0 0;padding:8px;border:1px solid var(--b);border-radius:8px;background:var(--bg)}
.xp .steps{margin:6px 0}
</style>""")


def written_request(site: str) -> str:
    """Generic erasure email to paste. Placeholders only; nothing is sent and no address is filled in."""
    from .tools.erasure import _LAW
    subject, law = _LAW["gdpr"]
    return (f"Subject: {subject}\n\nTo the privacy team at {site},\n\n{law}\n\n"
            "The email address concerned is: [YOUR EMAIL ADDRESS]\n"
            "Please confirm in writing once the data has been erased. If you need to verify my identity, "
            "tell me the minimum you need.\n\nThank you,\n[YOUR NAME]")


def _optout_card(e: dict) -> str:
    verified = bool(e.get("verified"))
    status = (f'<span class="chip ok">verified {_e(e.get("last_verified") or "", 12)}</span>' if verified
              else '<span class="chip todo">researched, not tested</span>')
    chips = []
    if e.get("requires_email_confirmation"):
        chips.append("confirm by email")
    if e.get("needs_captcha"):
        chips.append("bot check: you click it")
    if e.get("opt_out_email"):
        chips.append("written request")
    chips_html = "".join(f'<span class="chip">{_e(c, 40)}</span>' for c in chips)
    link = _link(e.get("opt_out_url") or "", "Open the removal page")
    src = _link(e.get("source_url") or "", "Where this route came from")
    mail = ""
    if e.get("opt_out_email"):
        mail = (f'<div class="foot">Send to: <b>{_e(e["opt_out_email"], 80)}</b></div>'
                f'<details><summary>Draft email (copy and paste)</summary><pre>{_e(written_request(e["name"]), 1500)}</pre></details>')
    return (f'<div class="card"><div class="nm">{_e(e["name"], 60)}</div>'
            f'<div style="margin:6px 0">{status}{chips_html}</div>'
            f'<div class="steps">{_e(e.get("steps_summary"), 600)}</div>'
            f'<div class="foot">{link}{" &middot; " + src if src else ""}</div>{mail}</div>')


def render_optout_html(entries: list[dict]) -> str:
    sites = [e for e in entries if e.get("category") == "lookup_service"]
    if not sites:
        return html_notice("No OSINT-site routes are loaded.")
    out = [OPTOUT_CSS, '<div class="xp"><h3>Opt out of OSINT lookup sites</h3>'
           '<p class="sub">These sites can profile an email or username. Each route was researched from the '
           'site\'s own page or a guide. Only entries marked <b>verified</b> have been tested, so confirm the steps '
           'on the site. We do not know which of these sites actually list you: most hide that behind a bot check.</p>']
    for tier in (1, 2, 3):
        group = sorted((e for e in sites if _tier(e) == tier), key=lambda e: e["name"].lower())
        if group:
            out.append(f'<h3>{_e(TIER_NAMES[tier], 80)} ({len(group)})</h3><div class="grid">' +
                       "".join(_optout_card(e) for e in group) + "</div>")
    out.append("</div>")
    return "".join(out)


# ---------------------------------------------------------------- UI glue (no Gradio import)

AGENT_HINT = ("_This tab fills in only when you run the agentic audit (open the accordion above). "
              "The plain scan does not write a summary._")
UI_OUTPUTS = 5  # trace, report, opt-out checklist, erasure drafts, files


def write_files(bundle: dict) -> list:
    d = tempfile.mkdtemp(prefix="redactor-")
    md, js = os.path.join(d, "exposure-report.md"), os.path.join(d, "exposure-report.json")
    with open(md, "w", encoding="utf-8") as f:
        f.write(bundle["report_md"])
    with open(js, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in bundle.items() if k not in ("report_md", "report_html")}, f, indent=2, default=str)
    return [md, js]


def ui_scan(mode, email, username, pivot=False, dispatch_fn=dispatch, entries=None, routes=None):
    """Yields 5-tuples: (trace, report, checklist, drafts, files)."""
    entries = load_entries() if entries is None else entries
    routes = load_routes() if routes is None else routes
    trace = []
    try:
   for ev in run_scan(mode, email, username, dispatch_fn=dispatch_fn, routes=routes, pivot=pivot):
            if ev["type"] == "step":
                trace.append("- " + ev["text"])
                t = "\n".join(trace)
                yield (t, html_notice("Scan running... please wait", "This can take a few minutes. Keep this page and the terminal open."), "", "", None)
            else:
                b = ev["bundle"]
                yield ("\n".join(trace), b["report_html"], render_optout_html(entries), AGENT_HINT, write_files(b))
    except ValueError as e:
        yield (f"### Cannot start the scan\n\n**{e}**", html_notice("Cannot start the scan", str(e)), "", "", None)


_URL_RE = __import__("re").compile(r"https?://[^\s)>\]\"'`]+|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def ungrounded_links(text: str, events: list) -> list:
    """Links or email addresses in the agent's answer that no tool result contains (likely invented)."""
    seen = json.dumps([e.get("result") for e in events if e.get("type") == "observation"], default=str).lower()
    out = []
    for m in _URL_RE.findall(text or ""):
        m = m.rstrip(".,;:*")
        if m.lower() not in seen and m not in out:
            out.append(m)
    return out


_VERIFIED_RE = __import__("re").compile(
    r"(?<![\w-])(?<!not )(?<!no )(?<!un)(?<!n't )(?<!never )verified\b(?!\s*(=|:)?\s*false)", __import__("re").I)


def unsupported_verified(text: str, events: list) -> bool:
    """True if the answer calls something 'verified' but no tool result says verified is true."""
    if not _VERIFIED_RE.search(text or ""):
        return False
    return not any('"verified": true' in json.dumps(e.get("result"), default=str).lower()
                   for e in events if e.get("type") == "observation")


def merged_from_events(events: list, routes=None) -> dict:
    """Build the same merged report from the tool results an agent run produced."""
    obs = {}
    users = []
    for ev in events:
        if ev.get("type") != "observation":
            continue
        if ev["name"] == "username_scan":
            users.append(ev["result"])
        else:
            obs[ev["name"]] = ev["result"]
    email_res = obs.get("email_scan") or obs.get("footprint_probe")
    return merge_findings(email_scan=email_res, username_scans=users or None, breach=obs.get("breach_lookup"),
                          routes=routes if routes is not None else {}, profiles=obs.get("public_profiles"))


def agent_extras(events: list, entries: list) -> str:
    """Parts of the summary that code writes, so they are complete: checklist counts and every draft made."""
    sites = [e for e in entries if e.get("category") == "lookup_service"]
    out = []
    if sites:
        n = {t: sum(_tier(e) == t for e in sites) for t in (1, 2, 3)}
        out.append(f"\n\n---\n**Opt-out checklist:** the next tab lists all {len(sites)} OSINT lookup sites with steps: "
                   f"{n[1]} are a form plus an email link or code, {n[2]} need a bot check you click, "
                   f"{n[3]} are a written email request.")
    drafts = [e["result"]["data"] for e in events
              if e.get("type") == "observation" and e.get("name") == "draft_erasure_request"
              and e["result"].get("status") == "ok"]
    breached = [b.get("name") if isinstance(b, dict) else str(b)
                for e in events if e.get("type") == "observation" and e.get("name") == "breach_lookup"
                and e["result"].get("status") == "ok"
                for b in (e["result"].get("data") or {}).get("breaches", [])]
    platforms = " ".join(d["platform"].lower() for d in drafts)
    missing = [b for b in breached if b and "".join(c for c in b.lower() if c.isalnum()) not in
               "".join(c for c in platforms if c.isalnum())]
    if missing:
        out.append("\n\n**No draft was made for:** " + ", ".join(missing) +
                   ". Run the agentic audit again if you want one.")
    if drafts:
        out.append("\n\n**Drafts the agent produced** (nothing was sent; you send them yourself):")
        for d in drafts:
            out.append(f"\n\n*{d['platform']}*\n\n```\n{d['body']}\n```")
    return "".join(out)


def ui_agent(email, jurisdiction, backend, full_name=None, max_steps=14, dispatch_fn=dispatch,
             entries=None, routes=None):
    """Agentic run for the page. Yields 5-tuples: (trace, report_html, checklist, agent_summary_md, files).

    The report is built from the agent's own tool results (so it is grounded); the agent's written
    answer goes in its own tab as Markdown.
    """
    from .agent import format_event, run_agent
    entries = load_entries() if entries is None else entries
    routes = load_routes() if routes is None else routes
    trace, events, final = [], [], None
    try:
        for ev in run_agent(validate_email(email), jurisdiction, backend, max_steps=max_steps,
                            dispatch_fn=dispatch_fn, full_name=(full_name or None)):
            events.append(ev)
            trace.append(format_event(ev))
            if ev["type"] == "final":
                final = ev
            yield ("\n\n".join(trace), html_notice("Agent running... please wait",
                   "The model is choosing tools. Keep this page and the terminal open."), "", "", None)
    except ValueError as e:
        yield (f"**Error:** {e}", html_notice("Cannot start", str(e)), "", "", None)
        return
    merged = merged_from_events(events, routes)
    bundle = {"mode": "agent", "merged": merged, "events": events,
              "report_md": render_exposure(merged), "report_html": render_cards_html(merged)}
    if events and events[-1]["type"] == "error":
        yield ("\n\n".join(trace), html_notice("The agent run failed", events[-1]["text"]), "", "", None)
        return
    note = ""
    bad = ungrounded_links(final["text"], events) if final else []
    if bad:
        note += ("> **Warning:** the agent wrote these links or addresses, but no tool returned them, so they may "
                 "be wrong. Do not rely on them without checking the site yourself: " + ", ".join(f"`{b}`" for b in bad) + "\n\n")
    if final and unsupported_verified(final["text"], events):
        note += ("> **Warning:** the agent calls a route \"verified\", but no tool result says any route was "
                 "verified. Treat those routes as researched, not tested.\n\n")
    if final and (final.get("truncated") or final.get("forced")):
        note = ("_The agent hit its step limit, so this answer was cut short._\n\n")
    yield ("\n\n".join(trace), bundle["report_html"], render_optout_html(entries),
           note + (final["text"] if final else "") + agent_extras(events, entries), write_files(bundle))
