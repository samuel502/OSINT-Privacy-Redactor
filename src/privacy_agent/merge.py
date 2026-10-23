"""Merge layer: turn separate tool results into one honest report. Plain Python, no model.

Inputs are the uniform tool results (`schema.result`). Output is one dict:
  accounts        de-duplicated, each labelled `confirmed` or `possible_match`, with sources
  breaches        breach names
  could_not_check plain-language list of anything that did not run or was only partly checked
  summary         counts, plus which checks worked and which failed

Rules this module enforces (they mirror CLAUDE.md):
  * `confirmed` = the site itself reported the email as registered. Nothing else earns it.
  * A username hit is `possible_match`: the handle may belong to someone else.
  * `unavailable` / `error` / skipped / blocked sites are listed, never read as "nothing found".
  * A removal route that is not verified is labelled `unverified`.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

# Sites that changed domain or have several. Extend as the registry grows.
DOMAIN_ALIASES = {"twitter.com": "x.com", "mobile.twitter.com": "x.com", "office365.com": "office.com"}

# Links that point at a store or host, not at the service itself. Fall back to the site name.
STORE_HOSTS = {"play.google.com", "apps.apple.com", "itunes.apple.com", "chrome.google.com",
               "chromewebstore.google.com", "github.com", "web.archive.org"}

CHECK_NAMES = {"email_scan": "email accounts", "username_scans": "username search", "breach": "breaches",
               "profiles": "public profiles (Gravatar, GitHub)"}


def domain_key(site: str, url: str = "") -> str:
    """Stable key for one site: its domain when there is one, else the normalised name."""
    host = ""
    if url:
        try:
            host = (urlsplit(url if "//" in url else "//" + url).hostname or "").lower()
        except ValueError:
            host = ""
    host = re.sub(r"^www\.", "", host)
    if host in STORE_HOSTS and site:
        host = ""
    if host:
        return DOMAIN_ALIASES.get(host, host)
    name = re.sub(r"[^a-z0-9]", "", (site or "").lower())
    return DOMAIN_ALIASES.get(name, f"name:{name}")


def routes_by_domain(entries: list) -> dict:
    """Index registry/playbook entries by the same key merge_findings uses (domain + aliases)."""
    out: dict = {}
    for e in entries:
        for name in [e.get("domain", ""), *e.get("aliases", [])]:
            if "." in name:
                out.setdefault(domain_key("", name), e)
        for name in [e.get("name", ""), *e.get("aliases", [])]:  # sites reported without a usable link
            if name and "." not in name:
                out.setdefault(domain_key(name, ""), e)
    return out


def _failed(res: dict, label: str, failed: list, notes: list) -> bool:
    """True when the tool did not produce a usable answer; records why."""
    if res is None:
        return True
    if res.get("status") != "ok":
        failed.append(label)
        why = res.get("error") or "no usable answer"
        notes.append(f"{label}: could not check ({why}). This is NOT a 'nothing found'.")
        return True
    return False


def _add(accounts: dict, key: str, site: str, url: str, evidence: str, source: str, details,
         category: str = "", avatar: str = ""):
    a = accounts.setdefault(key, {"domain": key, "site": site, "url": url, "evidence": [],
                                  "sources": [], "details": {},
                                  "category": "", "avatar": ""})
    if evidence not in a["evidence"]:
        a["evidence"].append(evidence)
    if source and source not in a["sources"]:
        a["sources"].append(source)
    if details:
        a["details"].update(details)
    if url and not a["url"]:
        a["url"] = url
    if category and not a["category"]:
        a["category"] = category
    if avatar and not a["avatar"]:
        a["avatar"] = avatar


def _removal(key: str, routes: dict | None) -> dict:
    entry = (routes or {}).get(key)
    if not entry:
        return {"status": "no_route_known", "url": None}
    return {"status": "verified" if entry.get("verified") else "unverified",
            "url": entry.get("opt_out_url") or entry.get("opt_out_email")}


def merge_findings(email_scan: dict | None = None, username_scans: list | None = None,
                   breach: dict | None = None, routes: dict | None = None,
                   profiles: dict | None = None) -> dict:
    accounts: dict = {}
    failed: list = []
    ok: list = []
    notes: list = []

    if email_scan is not None and not _failed(email_scan, CHECK_NAMES["email_scan"], failed, notes):
        ok.append(CHECK_NAMES["email_scan"])
        data = email_scan.get("data") or {}
        for h in data.get("hits", []):
            _add(accounts, domain_key(h.get("site", ""), h.get("url", "")), h.get("site", ""),
                 h.get("url", ""), "email_registered", h.get("source", "email_scan"), h.get("details"),
                 h.get("category", ""), h.get("avatar", ""))
        for d in data.get("confirmed_accounts", []):  # holehe fallback shape
            _add(accounts, domain_key(d, d), d, "", "email_registered", email_scan.get("source", ""), None)
        if data.get("errors"):
            notes.append(f"{data['errors']} sites errored or were blocked during the email scan and were not checked.")
        if data.get("skipped"):
            notes.append(f"{data['skipped']} sites were skipped in the email scan because checking them can "
                         "trigger a password-reset email to the owner.")

    for i, us in enumerate(username_scans or []):
        label = CHECK_NAMES["username_scans"]
        if _failed(us, label, failed, notes):
            continue
        if label not in ok:
            ok.append(label)
        data = us.get("data") or {}
        for h in data.get("hits", []):
            _add(accounts, domain_key(h.get("site", ""), h.get("url", "")), h.get("site", ""),
                 h.get("url", ""), "username_match", h.get("source", "username_scan"), h.get("details"),
                 h.get("category", ""), h.get("avatar", ""))
            acc = accounts[domain_key(h.get("site", ""), h.get("url", ""))]
            if h.get("url") and not acc.get("profile_url"):
                acc["profile_url"] = h["url"]
        if data.get("errors"):
            notes.append(f"{data['errors']} sites errored or were blocked during a username search and were not checked.")

    if profiles is not None and not _failed(profiles, CHECK_NAMES["profiles"], failed, notes):
        ok.append(CHECK_NAMES["profiles"])
        for p in (profiles.get("data") or {}).get("profiles", []):
            ev = "public_profile" if p.get("label") == "public_profile" else "username_match"
            key = domain_key(p.get("site", ""), p.get("url", ""))
            _add(accounts, key, p.get("site", ""), p.get("url", ""), ev, p.get("via", "profiles"),
                 p.get("details"), p.get("category", ""), p.get("avatar", ""))
            if p.get("profile_url"):
                accounts[key]["profile_url"] = p["profile_url"]
            if p.get("note"):
                accounts[key]["note"] = p["note"]
            if p.get("label") == "linked_profile":
                accounts[key]["listed_by"] = p.get("via", "")

    breach_names: list = []
    if breach is not None and not _failed(breach, CHECK_NAMES["breach"], failed, notes):
        ok.append(CHECK_NAMES["breach"])
        for b in (breach.get("data") or {}).get("breaches", []):
            name = b.get("name") if isinstance(b, dict) else str(b)
            if name and name not in breach_names:
                breach_names.append(name)

    out = []
    for a in accounts.values():
        a["label"] = "confirmed" if ({"email_registered", "public_profile"} & set(a["evidence"])) else "possible_match"
        a["removal"] = _removal(a["domain"], routes)
        out.append(a)
    out.sort(key=lambda a: (a["label"] != "confirmed", a["site"].lower()))

    return {
        "accounts": out,
        "breaches": breach_names,
        "could_not_check": notes,
        "summary": {
            "confirmed": sum(a["label"] == "confirmed" for a in out),
            "possible": sum(a["label"] == "possible_match" for a in out),
            "breaches": len(breach_names),
            "checks_ok": ok,
            "checks_failed": failed,
            "with_removal_route": sum(a["removal"]["status"] != "no_route_known" for a in out),
        },
    }
