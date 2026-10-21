"""Readable report from tool results. Plain Python: no LLM, no network, easy to test.

Two renderers, deliberately:
  render_markdown()  -> Gradio and saved files (tables, links, collapsible lists)
  render_terminal()  -> CLI (no HTML, wrapped to width, aligned columns)

The terminal one exists because a markdown table and a `<details>` tag are both unreadable
when they are printed as literal text.
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timezone

# Friendly service names. Anything missing falls back to a prettified domain.
DISPLAY = {
    "office365.com": "Microsoft 365 / Outlook", "outlook.com": "Microsoft 365 / Outlook",
    "live.com": "Microsoft 365 / Outlook", "twitter.com": "X (Twitter)", "x.com": "X (Twitter)",
    "google.com": "Google", "gmail.com": "Google", "youtube.com": "YouTube",
    "github.com": "GitHub", "discord.com": "Discord", "instagram.com": "Instagram",
    "snapchat.com": "Snapchat", "pinterest.com": "Pinterest", "reddit.com": "Reddit",
    "spotify.com": "Spotify", "yahoo.com": "Yahoo", "ebay.com": "eBay", "imgur.com": "Imgur",
    "patreon.com": "Patreon", "tumblr.com": "Tumblr", "venmo.com": "Venmo", "vrbo.com": "Vrbo",
    "last.fm": "Last.fm", "eventbrite.com": "Eventbrite", "evernote.com": "Evernote",
    "nike.com": "Nike", "samsung.com": "Samsung", "strava.com": "Strava",
    "soundcloud.com": "SoundCloud", "ok.ru": "OK.ru", "rambler.ru": "Rambler", "xing.com": "Xing",
    "vsco.co": "VSCO", "myspace.com": "Myspace", "pornhub.com": "Pornhub", "redtube.com": "RedTube",
    "firefox.com": "Mozilla / Firefox", "atlassian.com": "Atlassian", "garmin.com": "Garmin",
    "bitmoji.com": "Bitmoji", "smule.com": "Smule", "voxmedia.com": "Vox Media",
    "codecademy.com": "Codecademy", "blablacar.com": "BlaBlaCar", "deliveroo.com": "Deliveroo",
    "buymeacoffee.com": "Buy Me a Coffee", "rocketreach.co": "RocketReach", "about.me": "About.me",
    "tunefind.com": "Tunefind", "issuu.com": "Issuu", "komoot.com": "Komoot",
    "cracked.to": "Cracked.to", "ello.co": "Ello", "7cups.com": "7 Cups",
    "pipedrive.com": "Pipedrive", "nimble.com": "Nimble", "nocrm.io": "noCRM",
    "nutshell.com": "Nutshell", "teamleader.eu": "TeamLeader", "amocrm.com": "amoCRM",
    "cpaelites.com": "CPA Elites", "cpahero.com": "CPA Hero", "clashfarmer.com": "ClashFarmer",
    "crevado.com": "Crevado", "badeggsonline.com": "Bad Eggs Online", "bios-mods.com": "BIOS-Mods",
    "bluegrassrivals.com": "Bluegrass Rivals", "blackworldforum.com": "Black World Forum",
    "chinaphonearena.com": "China Phone Arena", "babeshows.co.uk": "Babeshows",
    "demonforums.net": "DemonForums", "thecardboard.org": "The Cardboard",
    "thevapingforum.com": "The Vaping Forum", "onlinesequencer.net": "Online Sequencer",
    "nattyornotforum.nattyornot.com": "Natty or Not forum",
    "drachenhort.user.stunet.tu-freiberg.de": "TU Freiberg (Drachenhort)",
    "forum.blitzortung.org": "Blitzortung forum", "forum.codeigniter.com": "CodeIgniter forum",
    "forum.kodi.tv": "Kodi forum", "forum.ndemiccreations.com": "Ndemic Creations forum",
    "forums.nextpvr.com": "NextPVR forums", "forums.therian-guide.com": "Therian Guide forums",
    "discussion.cambridge-mt.com": "Cambridge MT forum",
    "emailosint.org": "EmailOSINT", "fingerprint.to": "Fingerprint.to",
    "osintleak.com": "OSINTLeak", "epieos.com": "Epieos",
    "haveibeenpwned.com": "Have I Been Pwned", "fingerprint.com": "Fingerprint (device)",
    "gravatar.com": "Gravatar", "leakcheck.io": "LeakCheck", "hunter.io": "Hunter.io",
    "signalhire.com": "SignalHire", "lusha.com": "Lusha", "snov.io": "Snov.io",
    "contactout.com": "ContactOut", "zoominfo.com": "ZoomInfo", "apollo.io": "Apollo.io",
}

# Track A: these profile you *from your email address* — "stop being findable".
PROFILE_CATEGORIES = {"lookup_service", "aggregator", "browser_config"}


def _first(routes, domain):
    entries = (routes or {}).get(domain) or []
    return entries[0] if entries else None


def _prettify(domain: str) -> str:
    if not domain:
        return "?"
    parts = [p for p in domain.split(".") if p]
    stem = parts[-2] if len(parts) >= 2 else (parts[0] if parts else domain)
    if stem in {"co", "com", "org", "net", "user"} and len(parts) >= 3:
        stem = parts[-3]
    return stem.replace("-", " ").replace("_", " ").strip().title() or domain


def display_name(domain: str, routes=None) -> str:
    e = _first(routes, domain)
    if e and e.get("name"):
        return e["name"]
    return DISPLAY.get((domain or "").lower()) or _prettify(domain)


def effort_label(entry) -> str:
    """What the user actually has to do. Never a vague 'guided'."""
    e = entry or {}
    if not (e.get("opt_out_url") or e.get("opt_out_email")):
        return "send draft"
    t = e.get("opt_out_type")
    if t == "email":
        return "email"
    if t == "browser_config":
        return "settings"
    if t == "web_form":
        return "page + captcha" if e.get("needs_captcha") else "web form"
    return "open page"


def _where(item):
    """Link for a checklist item or a raw playbook match. The two carry different key names."""
    label = item.get("service") or item.get("name") or item.get("domain") or "?"
    url = item.get("url") or item.get("opt_out_url")
    mail = item.get("mailto") or item.get("opt_out_email")
    if url:
        return f"[{label}]({url})"
    if mail:
        return f"email `{mail}`"
    return "_no route on file: send an erasure request_"


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
            "track": "B", "service": display_name(d, routes), "domain": d, "kind": "account",
            "why": "appears in a known breach" if hit else "account registered to this email",
            "url": e.get("opt_out_url"), "mailto": e.get("opt_out_email"),
            "auto": effort_label(e), "verified": bool(e.get("verified")),
            "priority": 1 if hit else 2,
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
                "track": "A", "service": e.get("name") or display_name(d), "domain": d,
                "kind": e.get("category"),
                "why": ("fingerprints your device, not your email" if browser
                        else "profiles you from your email address"),
                "url": e.get("opt_out_url"), "mailto": e.get("opt_out_email"),
                "auto": effort_label(e), "verified": bool(e.get("verified")),
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
            where = _where(i) + ("" if i.get("verified") else " *(unverified)*")
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
                    L.append(f"| {display_name(d)} | [{m['name']} removal page]({m['opt_out_url']}) | {status} |")
                else:
                    L.append(f"| {display_name(d)} | no playbook yet: send an erasure request | n/a |")
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
            L.append(f"- {_where(m)}{ver}:{extra} {m.get('steps_summary', '')}")

    if checklist:
        L += ["", "## Do this first", "", render_checklist(checklist)]
    if drafts:
        L += ["", "## Erasure drafts (nothing is sent automatically)", "", render_drafts(drafts)]
    return "\n".join(L)


# --------------------------------------------------------------------------- terminal

def _wrap(text: str, width: int, indent: str = "    ") -> list:
    return textwrap.wrap(text, width=width - len(indent)) or [""]


def _cols(rows, width: int, gap: int = 2) -> list:
    """Two aligned columns: (left, right)."""
    if not rows:
        return []
    w = min(max(len(l) for l, _ in rows), max(24, width // 3))
    return [f"  {l[:w].ljust(w)}{' ' * gap}{r}".rstrip() for l, r in rows]


def _rule(label: str, width: int) -> str:
    return f"\n  {label}\n  " + "─" * (width - 2)


def render_terminal(footprint, breaches, playbooks, lookup_services, *,
                    drafts=None, checklist=None, email=None, width: int = 88) -> str:
    """Plain-text report: no HTML, wrapped, aligned. For the CLI."""
    W = max(60, width)
    L = ["", "  PRIVACY FOOTPRINT REPORT"]
    if email:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        L.append(f"  {email}   ·   {stamp}")

    # coverage + accounts
    fd = footprint.get("data", {})
    L.append(_rule("ACCOUNTS", W))
    if footprint.get("status") != "ok":
        L += _wrap("The account check could not run: " + str(footprint.get("error")), W)
    else:
        acc = fd.get("confirmed_accounts", [])
        lim = fd.get("rate_limited_or_unchecked", [])
        c = fd.get("holehe_counts", {})
        total = c.get("registered", 0) + c.get("not_registered", 0) + c.get("rate_limited", 0)
        if total:
            L += _wrap(f"{total - len(lim)} of {total} sites probed · "
                       f"{len(lim)} blocked by rate limits and NOT checked", W)
        if acc:
            rows = []
            for d in acc:
                m = (playbooks.get(d, {}).get("data", {}).get("matches") or [None])[0]
                rows.append((display_name(d), effort_label(m)))
            L += _cols(rows, W)
        else:
            L += ["  none confirmed"]

    # breaches
    L.append(_rule("BREACHES", W))
    if breaches.get("status") != "ok":
        L += _wrap("The breach check could not run: " + str(breaches.get("error")), W)
    else:
        names = breaches.get("data", {}).get("breaches", [])
        if names:
            L += _wrap(f"{len(names)} known: " + ", ".join(names), W)
        else:
            L += _wrap("none known (not proof of safety)", W)

    # lookup sites
    if lookup_services:
        L.append(_rule("OPT OUT OF THE SITES THAT PROFILE YOU", W))
        rows = []
        for m in lookup_services:
            label = display_name(m.get("domain") or m.get("name", ""))
            if not m.get("verified"):
                label += " (unverified)"
            rows.append((label, effort_label(m)))
        L += _cols(rows, W)
        L += _wrap("Opting out of one does not opt you out of the others, and it removes you "
                   "from that site's answer, not the breach data underneath.", W)

    # checklist
    if checklist:
        L.append(_rule("DO THIS FIRST", W))
        for track, title in (("A", "Stop being findable"), ("B", "Shrink the footprint")):
            rows = [i for i in checklist if i["track"] == track]
            if not rows:
                continue
            L += ["", f"  {title}"]
            L += _cols([(f"{n}. {i['service']}", i["auto"]) for n, i in enumerate(rows, 1)], W)
            for n, i in enumerate(rows, 1):
                dest = i.get("url") or (f"email {i['mailto']}" if i.get("mailto") else "no route on file")
                dest = dest.replace("https://", "")
                L += _wrap(f"{n}. {dest}", W, "       ")

    # drafts
    if drafts:
        L.append(_rule("ERASURE DRAFTS (nothing is sent automatically)", W))
        for d in drafts:
            L += ["", f"  {d.get('platform')} — {d.get('subject')}"]
            L += _wrap(f"To: {d.get('platform')}", W, "      ")
        L += _wrap("Full text is in the saved report.", W)

    if not checklist and not drafts:
        L.append(_rule("NOTHING TO ACTION", W))
    return "\n".join(L)
