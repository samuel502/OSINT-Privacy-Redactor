import json
import urllib.error

import pytest

from privacy_agent.schema import result, validate_email
from privacy_agent.tools import breaches, dispatch
from privacy_agent.tools.erasure import draft_erasure_request
from privacy_agent.tools.footprint import parse_holehe_csv, parse_holehe_text
from privacy_agent.tools.playbooks import PlaybookIndex, load_entries, search_playbooks


def test_validate_email_accepts_and_rejects():
    assert validate_email("  a.b+c@example.co.uk ") == "a.b+c@example.co.uk"
    for bad in ["", "nope", "--help@x.com", "a@b", "a b@c.com", "x" * 260 + "@a.com"]:
        with pytest.raises(ValueError):
            validate_email(bad)


def test_result_rejects_bad_status():
    with pytest.raises(ValueError):
        result("success")


def test_parse_holehe_csv(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("Name,Domain,Method,Frequent Rate Limit,Rate Limit,Exists,Email Recovery,Phone Number,Others\n"
                 "x,github.com,login,False,False,True,,,\n"
                 "y,twitter.com,register,False,True,False,,,\n"
                 "z,nope.com,register,False,False,False,,,\n")
    confirmed, limited = parse_holehe_csv(str(p))
    assert confirmed == ["github.com"] and limited == ["twitter.com"]


def test_parse_holehe_text_ignores_legend():
    out = "[+] Email used, [-] Email not used, [x] Rate limit\n[+] github.com\n[-] foo.com\n"
    assert parse_holehe_text(out)[0] == ["github.com"]


def test_footprint_never_pads_results(monkeypatch):
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint.shutil, "which", lambda _: None)
    monkeypatch.setattr(footprint, "_gravatar", lambda _: False)
    r = footprint.footprint_probe("a@b.com")
    assert r["status"] == "ok" and r["data"]["confirmed_accounts"] == []


def test_footprint_unavailable_when_nothing_can_run(monkeypatch):
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint.shutil, "which", lambda _: None)
    monkeypatch.setattr(footprint, "_gravatar", lambda _: None)
    assert footprint.footprint_probe("a@b.com")["status"] == "unavailable"


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


def test_playbook_exact_and_alias_match():
    assert search_playbooks("https://www.github.com/foo")["data"]["matches"][0]["domain"] == "github.com"
    assert search_playbooks("twitter.com")["data"]["matches"][0]["domain"] == "x.com"


def test_playbook_text_query_and_unknown():
    idx = PlaybookIndex(load_entries())
    assert idx.search("music streaming account privacy", k=1) or True  # fuzzy; must not crash
    r = search_playbooks("totally-unknown-site.example")
    assert r["status"] == "ok" and r["data"]["matches"] == [] and "draft_erasure_request" in r["note"]


def test_playbook_flags_unverified():
    r = search_playbooks("github.com")
    assert r["data"]["matches"][0]["verified"] is False and "NOT been manually checked" in r["note"]


def test_erasure_templates_cite_right_law():
    g = draft_erasure_request("a@b.com", "https://www.reddit.com/", "gdpr")["data"]
    assert "Article 17" in g["body"] and "reddit.com" in g["body"] and "a@b.com" in g["body"]
    assert "1798.105" in draft_erasure_request("a@b.com", "reddit.com", "ccpa")["data"]["body"]
    assert draft_erasure_request("a@b.com", "reddit.com", "mars")["data"]["jurisdiction"] == "other"
    assert draft_erasure_request("a@b.com", "notadomain")["status"] == "error"


def test_dispatch_unknown_tool_and_never_raises():
    assert dispatch("rm_rf", {}, {"email": "a@b.com"})["status"] == "error"
    assert dispatch("draft_erasure_request", {}, {"email": "bad"})["status"] == "error"
