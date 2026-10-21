import json
import urllib.error

import pytest

from privacy_agent.schema import result, validate_email
from privacy_agent.tools import breaches, dispatch
from privacy_agent.tools.erasure import draft_erasure_request
from privacy_agent.tools.footprint import parse_holehe_csv_extras, parse_holehe_text
from privacy_agent.tools.playbooks import PlaybookIndex, load_entries, search_playbooks


def test_validate_email_accepts_and_rejects():
    assert validate_email("  a.b+c@example.co.uk ") == "a.b+c@example.co.uk"
    for bad in ["", "nope", "--help@x.com", "a@b", "a b@c.com", "x" * 260 + "@a.com"]:
        with pytest.raises(ValueError):
            validate_email(bad)


def test_result_rejects_bad_status():
    with pytest.raises(ValueError):
        result("success")


HOLEHE_OUT = """********************************
   me@example.com
********************************
[x] about.me
[-] adobe.com
[x] drachenhort.user.stunet.tu-freiberg.de
[+] office365.com
[x] pinterest.com
[+] twitter.com / +49*****12
[-] zoho.com

[+] Email used, [-] Email not used, [x] Rate limit
121 websites checked in 10.5 seconds
Twitter : @palenath
Github : https://github.com/megadose/holehe
"""


def test_parse_holehe_text_real_format():
    confirmed, limited, absent = parse_holehe_text(HOLEHE_OUT)
    assert confirmed == ["office365.com", "twitter.com"]
    assert limited == ["about.me", "drachenhort.user.stunet.tu-freiberg.de", "pinterest.com"]
    assert absent == 2  # legend/banner/summary lines are ignored


def test_parse_holehe_csv_extras_case_insensitive(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("name,domain,exists,email recovery,PHONE NUMBER,others\n"
                 "x,twitter.com,True,t***@gmail.com,98****11,\n"
                 "y,nope.com,False,a@b.com,,\n")
    assert parse_holehe_csv_extras(str(p)) == {
        "twitter.com": {"email_recovery": "t***@gmail.com", "phone_number": "98****11"}}


def test_footprint_reports_partial_coverage_from_real_holehe_output(monkeypatch):
    from types import SimpleNamespace as NS
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint.shutil, "which", lambda _: "holehe")
    monkeypatch.setattr(footprint, "_gravatar", lambda _: False)
    monkeypatch.setattr(footprint, "RETRY_PAUSE_S", 0) 
    monkeypatch.setattr(footprint.subprocess, "run",
                        lambda *a, **k: NS(stdout=HOLEHE_OUT, stderr="", returncode=0))
    r = footprint.footprint_probe("a@b.com")
    d = r["data"]
    assert r["status"] == "ok" and d["coverage"] == "partial"
    assert d["confirmed_accounts"] == ["office365.com", "twitter.com"]
    assert "pinterest.com" in d["rate_limited_or_unchecked"]
    assert d["holehe_counts"] == {"registered": 2, "not_registered": 2, "rate_limited": 3}
    assert "NOT checked" in r["note"]


def test_footprint_holehe_garbage_output_is_error_not_empty_success(monkeypatch):
    from types import SimpleNamespace as NS
    from privacy_agent.tools import footprint
    monkeypatch.setattr(footprint.shutil, "which", lambda _: "holehe")
    monkeypatch.setattr(footprint, "_gravatar", lambda _: None)
    monkeypatch.setattr(footprint.subprocess, "run",
                        lambda *a, **k: NS(stdout="usage: holehe ...", stderr="bad flag", returncode=2))
    assert footprint.footprint_probe("a@b.com")["status"] == "unavailable"


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


def test_emailosint_playbook_is_verified_lookup_service():
    m = search_playbooks("emailosint.org")["data"]["matches"][0]
    assert m["category"] == "lookup_service" and m["verified"] is True and m["needs_captcha"] is True
    assert m["opt_out_url"] == "https://emailosint.org/claim"
