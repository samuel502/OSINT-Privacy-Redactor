"""Readable report from tool results. Plain Python: no LLM, no network, easy to test."""

def build_report(footprint, breaches, playbooks, lookup_services):
    """Plain-Python report. No LLM, no network. Takes tool results (dicts), returns Markdown."""
    L = ["# Privacy footprint report", ""]

    # --- accounts ---
    fd = footprint.get("data", {})
    if footprint.get("status") != "ok":
        L += ["## Accounts", "The account check could not run: " + str(footprint.get("error")), ""]
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

    # --- breaches ---
    L += ["", "## Data breaches"]
    if breaches.get("status") != "ok":
        L.append("The breach check could not run: " + str(breaches.get("error")))
    else:
        names = breaches.get("data", {}).get("breaches", [])
        L.append(f"Found in **{len(names)}** known breach(es): " + ", ".join(names) if names
                 else "No known breaches found (this is not proof of safety).")

    # --- lookup services ---
    if lookup_services:
        L += ["", "## Opt out of email-lookup sites"]
        for m in lookup_services:
            extra = " Needs a CAPTCHA and an emailed confirmation link." if m.get("needs_captcha") else ""
            ver = "" if m.get("verified") else " (unverified)"
            L.append(f"- [{m['name']}]({m['opt_out_url']}){ver}:{extra} {m['steps_summary']}")
    return "\n".join(L)
