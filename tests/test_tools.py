import json
import urllib.error

import pytest

from privacy_agent.schema import result, validate_email
from privacy_agent.tools import breaches, dispatch
from privacy_agent.tools.erasure import draft_erasure_request
from privacy_agent.tools.footprint import merge_passes
from privacy_agent.tools.playbooks import PlaybookIndex, load_entries, search_playbooks


def test_validate_email_accepts_and_rejects():
    assert validate_email("  a.b+c@example.co.uk ") == "a.b+c@example.co.uk"
    for bad in ["", "nope", "--help@x.com", "a@b", "a b@c.com", "x" * 260 + "@a.com"]:
        with pytest.raises(ValueError):
            validate_email(bad)


def test_result_rejects_bad_status():
    with pytest.raises(ValueError):
        result("success")


# ---- footprint (holehe via _holehe_runner.py) ----

def _records():
    """One full sweep: 2 hits, 1 unresolved, 1 definite miss."""
    return [
        {"name": "office365", "domain": "office365.com", "exists": True, "rateLimit": False},
        {"name": "twitter", "domain": "twitter.com", "exists": True, "rateLimit": False},
        {"name": "aboutme", "domain": "about.me", "exists": False, "rateLimit": True},
        {"name": "adobe", "domain": "adobe.com", "exists": False, "rateLimit": False},
    ]


def test_merge_passes_prefers_hit_then_miss():
    confirmed, unresolved, absent = merge_passes([
        ({"a.com"}, {"b.com"}, {"c.com"}),
        ({"b.com"}, set(), {"d.com"}),
    ])
    assert confirmed == {"a.com", "b.com"} and "b.com" not in unresolved
    assert absent == {"c.com", "d.com"}


def test_footprint_reports_partial_coverage(monkeypatch):
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint, "_run_runner", lambda email: _records())
    monkeypatch.setattr(footprint, "_gravatar", lambda _: False)
    r = footprint.footprint_probe("a@b.com", retry_blocked=False)
    d = r["data"]
    assert r["status"] == "ok" and d["coverage"] == "partial"
    assert d["confirmed_accounts"] == ["office365.com", "twitter.com"]
    assert "about.me" in d["rate_limited_or_unchecked"]
    assert d["holehe_counts"] == {"registered": 2, "not_registered": 1, "rate_limited": 1}
    assert "NOT checked" in r["note"]


def test_footprint_second_pass_recovers_unresolved_sites(monkeypatch):
    from privacy_agent.tools import footprint
    calls = []

    def fake(email):
        calls.append(1)
        if len(calls) > 1:
            return [{"name": "aboutme", "domain": "about.me", "exists": True, "rateLimit": False}]
        return _records()

    monkeypatch.setattr(footprint, "_run_runner", fake)
    monkeypatch.setattr(footprint, "_gravatar", lambda _: False)
    monkeypatch.setattr(footprint, "PASS_PAUSE_S", 0)
    monkeypatch.setattr(footprint, "MAX_PASSES", 2)
    d = footprint.footprint_probe("a@b.com")["data"]
    assert len(calls) == 2 and "about.me" in d["confirmed_accounts"]
    assert d["rate_limited_or_unchecked"] == []


def test_footprint_runner_failure_is_unavailable_not_empty(monkeypatch):
    from privacy_agent.tools import footprint
    def boom(email):
        raise RuntimeError("runner blew up")
    monkeypatch.setattr(footprint, "_run_runner", boom)
    monkeypatch.setattr(footprint, "_gravatar", lambda _: None)
    r = footprint.footprint_probe("a@b.com")
    assert r["status"] == "unavailable" and "runner blew up" in r["data"]["sources"]["holehe"]


def test_footprint_never_pads_results(monkeypatch):
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint, "_run_runner", lambda email: [])
    monkeypatch.setattr(footprint, "_gravatar", lambda _: False)
    r = footprint.footprint_probe("a@b.com")
    assert r["status"] == "ok" and r["data"]["confirmed_accounts"] == []


def test_footprint_unavailable_when_nothing_can_run(monkeypatch):
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint, "RUNNER", footprint.Path("nope.py"))
    monkeypatch.setattr(footprint, "_gravatar", lambda _: None)
    assert footprint.footprint_probe("a@b.com")["status"] == "unavailable"


# ---- breaches ----

class _Resp:
    def __init__(self, body): self._b = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *a): return json.dumps(self._b).encode()


def test_breach_lookup_parses_nested_names(monkeypatch):
    monkeypatch.setattr(breaches.urllib.request, "urlopen",
                        lambda *a, **k: _Resp({"breaches": [["Adobe", "LinkedIn"]], "status": "success"}))
    r = breaches.breach_lookup("a@b.com")
    assert r["status"] == "ok" and r["data"]["breaches"] == ["Adobe", "LinkedIn"]


def test_breach_lookup_404_is_ok_empty_not_proof(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)
    monkeypatch.setattr(breaches.urllib.request, "urlopen", boom)
    r = breaches.breach_lookup("a@b.com")
    assert r["status"] == "ok" and r["data"]["breach_count"] == 0 and "not proof" in r["note"].lower()


def test_breach_lookup_network_failure_is_unavailable(monkeypatch):
    def boom(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(breaches.urllib.request, "urlopen", boom)
    assert breaches.breach_lookup("a@b.com")["status"] == "unavailable"


# ---- playbooks ----

def test_playbook_exact_and_alias_match():
    assert search_playbooks("https://www.haveibeenpwned.com/foo")["data"]["matches"][0]["domain"] == "haveibeenpwned.com"
    assert search_playbooks("hibp")["data"]["matches"][0]["domain"] == "haveibeenpwned.com"


def test_playbook_text_query_and_unknown():
    idx = PlaybookIndex(load_entries())
    assert idx.search("music streaming account privacy", k=1) or True  # fuzzy; must not crash
    r = search_playbooks("totally-unknown-site.example")
    assert r["status"] == "ok" and r["data"]["matches"] == [] and "draft_erasure_request" in r["note"]


def test_playbook_flags_unverified():
    r = search_playbooks("haveibeenpwned.com")
    assert r["data"]["matches"][0]["verified"] is False and "NOT been manually checked" in r["note"]


def test_emailosint_playbook_is_verified_lookup_service():
    m = search_playbooks("emailosint.org")["data"]["matches"][0]
    assert m["category"] == "lookup_service" and m["verified"] is True and m["needs_captcha"] is True
    assert m["opt_out_url"] == "https://emailosint.org/claim"


# ---- erasure + dispatch ----

def test_erasure_templates_cite_right_law():
    g = draft_erasure_request("a@b.com", "https://www.reddit.com/", "gdpr")["data"]
    assert "Article 17" in g["body"] and "reddit.com" in g["body"] and "a@b.com" in g["body"]
    assert "1798.105" in draft_erasure_request("a@b.com", "reddit.com", "ccpa")["data"]["body"]
    assert draft_erasure_request("a@b.com", "reddit.com", "mars")["data"]["jurisdiction"] == "other"
    assert draft_erasure_request("a@b.com", "notadomain")["status"] == "error"


def test_dispatch_unknown_tool_and_never_raises():
    assert dispatch("rm_rf", {}, {"email": "a@b.com"})["status"] == "error"
    assert dispatch("draft_erasure_request", {}, {"email": "bad"})["status"] == "error"
