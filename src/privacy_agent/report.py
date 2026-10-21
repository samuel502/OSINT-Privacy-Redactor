"""Readable report and actionable checklist from tool results.
Plain Python: no LLM, no network, deterministic and testable."""
from __future__ import annotations

_AUTO_LABEL = {
    "email": "email draft (you send it)",
    "web_form": "web form (CAPTCHA)",
    "browser_config": "browser settings",
    "guide": "guided",
    None: "guided",
}

# Track A: these profile you *from your email address* — "stop being findable".
PROFILE_CATEGORIES = {"lookup_service", "aggregator", "browser_config"}


def _first(routes, domain):
    entries = routes.get(domain) or []
    return entries[0] if entries else None


def build_checklist(footprint, breaches, routes) -> list:
    """Ordered, actionable plan. Deterministic. priority 1 = do first."""
    items, seen = [], set()
    breached = ({b.lower() for b in (breaches.get("data", {}).get("breaches") or [])}
                if breaches.get("status") == "ok" else set())
    accounts = (footprint.get("data", {}).get("confirmed_accounts", [])
                if footprint.get("status") == "ok" else [])

    for d in accounts:
        e = _first(routes, d) or {}
        hit = d.split(".")[0].lower() in breached
        items.append({
            "track": "B", "service": e.get("name") or d, "domain": d, "kind": "account",
            "why": "appears in a known breach" if hit else "account registered to this email",
            "url": e.get("opt_out_url"), "mailto": None,
            "auto": _AUTO_LABEL.get(e.get("opt_out_type")),
            "verified": bool(e.get("verified")), "priority": 1 if hit else 2,
        })
        seen.add(d)

    for d, entries in (routes or {}).items():
        if d in seen:
            continue
        for e in entries:
            if e.get("category") not in PROFILE_CATEGORIES:
                continue
            browser = e.get("category") == "browser_config"
            items.append({
                "track": "A", "service": e.get("name") or d, "domain": d,
                "kind": e.get("category"),
                "why": ("fingerprints your device, not your email" if browser
                        else "profiles you from your email address"),
                "url": e.get("opt_out_url"), "mailto": e.get("opt_out_email"),
                "auto": _AUTO_LABEL.get(e.get("opt_out_type")),
                "verified": bool(e.get("verified")),
                "priority": 4 if browser else 3,
            })
    items.sort(key=lambda i: (i["priority"], i["service"]))
    return items


def render_checklist(items) -> str:
    if not items:
        return "_Nothing to action._"
    out = []
    for track, title in (("A", "Stop being findable (opt out of the lookup sites)"),
                         ("B", "Shrink the footprint (the accounts behind the address)")):
        rows = [i for i in items if i["track"] == track]
        if not rows:
            continue
        out += [f"**{title}**", "", "| # | Service | Why | Where | Effort |", "|---|---|---|---|---|"]
        for n, i in enumerate(rows, 1):
            if i.get("url"):
                where = f"[{i['service']}]({i['url']})"
            elif i.get("mailto"):
                where = f"email `{i['mailto']}`"
            else:
                where = "_no route on file: send an erasure request_"
            if not i.get("verified"):
                where += " *(unverified)*"
            out.append(f"| {n} | {i['service']} | {i['why']} | {where} | {i['auto']} |")
        out.append("")
    return "\n".join(out)


def render_drafts(drafts) -> str:
    if not drafts:
        return "_No drafts generated._"
    out = []
    for d in drafts:
        out += [f"### {d.get('platform')}", "",
                f"**To:** privacy team at `{d.get('platform')}` — subject: `{d.get('subject')}`", "",
                "```text", (d.get("body") or "").rstrip(), "```", ""]
    return "\n".join(out)


def build_report(footprint, breaches, playbooks, lookup_services, *,
                 drafts=None, checklist=None, email=None):
    """Markdown report. `playbooks` maps domain -> tool result; `lookup_services` is a list."""
    L = ["# Privacy footprint report", ""]
    if email:
        L += [f"**Address audited:** `{email}`", ""]

    fd = footprint.get("data", {})
    if footprint.get("status") != "ok":
        L += ["## Accounts",
              "The account check could not run: " + str(footprint.get("error")), ""]
    else:
        acc = fd.get("confirmed_accounts", [])
        lim = fd.get("rate_limited_or_unchecked", [])
        c = fd.get("holehe_counts", {})
        total = c.get("registered", 0) + c.get("not_registered", 0) + c.get("rate_limited", 0)
        if total:
            L.append(f"**Coverage:** {total - len(lim)} of {total} sites checked; "
                     f"{len(lim)} were blocked by rate limits and **not checked**.")
        L += ["", f"## Accounts found ({len(acc)})"]
        if acc:
            L += ["| Service | How to remove it | Playbook status |", "|---|---|---|"]
            for d in acc:
                matches = playbooks.get(d, {}).get("data", {}).get("matches") or []
                m = matches[0] if matches else None
                if m and m.get("opt_out_url"):
                    status = "verified" if m.get("verified") else "unverified: confirm the steps yourself"
                    L.append(f"| {d} | [{m['name']} removal page]({m['opt_out_url']}) | {status} |")
                else:
                    L.append(f"| {d} | no playbook yet: send an erasure request | n/a |")
        else:
            L.append("None confirmed.")
        if lim:
            L += ["", f"<details><summary>{len(lim)} sites not checked (click to expand)</summary>", "",
                  ", ".join(lim), "", "</details>"]

    L += ["", "## Data breaches"]
    if breaches.get("status") != "ok":
        L.append("The breach check could not run: " + str(breaches.get("error")))
    else:
        names = breaches.get("data", {}).get("breaches", [])
        if names:
            L.append(f"Found in **{len(names)}** known breach(es): " + ", ".join(names))
        else:
            L.append("No known breaches found (this is not proof of safety).")

    if lookup_services:
        L += ["", "## Opt out of the sites that profile you",
              "", "_Opting out of one site does not opt you out of the others, and it removes you "
              "from that site's answer — not from the breach data underneath._", ""]
        for m in lookup_services:
            extra = " Needs a CAPTCHA and an emailed confirmation link." if m.get("needs_captcha") else ""
            ver = "" if m.get("verified") else " (unverified)"
            if m.get("opt_out_url"):
                where = f"[{m['name']}]({m['opt_out_url']})"
            elif m.get("opt_out_email"):
                where = f"{m['name']} — email `{m['opt_out_email']}`"
            else:
                where = f"{m['name']} — no route on file"
            L.append(f"- {where}{ver}:{extra} {m.get('steps_summary', '')}")

    if checklist:
        L += ["", "## Do this first", "", render_checklist(checklist)]
    if drafts:
        L += ["", "## Erasure drafts (nothing is sent automatically)", "", render_drafts(drafts)]
    return "\n".join(L)
