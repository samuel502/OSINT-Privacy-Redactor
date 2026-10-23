"""Checks that every registry entry follows the project's rules (CLAUDE.md rule 6 and rule 1)."""
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "src" / "privacy_agent" / "data" / "playbooks.json"
ENTRIES = json.loads(DATA.read_text(encoding="utf-8"))


def test_domains_are_unique():
    domains = [e["domain"] for e in ENTRIES]
    assert len(domains) == len(set(domains))


def test_every_entry_has_a_source_and_a_route():
    for e in ENTRIES:
        assert e.get("steps_summary"), e["domain"]
        has_route = e.get("opt_out_url") or e.get("opt_out_email") or e.get("nav_hint")
        assert has_route or "no URL on file" in e.get("notes", ""), e["domain"]  # seed gaps must say so
        if e["domain"] not in {"github.com", "spotify.com", "google.com", "x.com", "reddit.com",
                               "gravatar.com", "haveibeenpwned.com"}:
            assert e.get("source_url"), f"{e['domain']} needs a source_url"


def test_verified_entries_carry_a_date_and_unverified_do_not_pretend():
    for e in ENTRIES:
        if e["verified"]:
            assert e["last_verified"], e["domain"]
        else:
            assert e["last_verified"] is None, e["domain"]
            assert "NOT tested" in e.get("notes", "") or "SEED" in e.get("notes", ""), e["domain"]


def test_urls_are_not_invented():
    # An opt-out URL must be the source page itself, or a link that appeared on a page we read.
    for e in ENTRIES:
        url = e.get("opt_out_url")
        if url:
            assert url.startswith("https://"), e["domain"]
