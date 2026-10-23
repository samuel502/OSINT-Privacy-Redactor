"""Offline tests for email_scan / username_scan. Fixture data is SYNTHETIC (sample, not live)."""
import json
import pathlib
import subprocess

import pytest

from privacy_agent.tools import dispatch, userscan

@pytest.fixture(autouse=True)
def _pretend_installed(monkeypatch):
    monkeypatch.setattr(userscan, "_installed", lambda: True)


FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "userscanner_email.json").read_text())


def test_parse_counts_and_labels():
    d = userscan.parse_rows(FIX, "email")
    assert d["hit_count"] == 2 and d["absent"] == 2 and d["errors"] == 1 and d["skipped"] == 1
    assert {h["site"] for h in d["hits"]} == {"ExampleShop", "ExampleSocial"}
    assert all(h["label"] == "registered" and h["source"] == "user-scanner" for h in d["hits"])


def test_username_hits_are_possible_matches_only():
    d = userscan.parse_rows(FIX, "username")
    assert all(h["label"] == "possible_match" for h in d["hits"])


def test_untrusted_profile_text_is_dropped():
    d = userscan.parse_rows(FIX, "email")
    blob = json.dumps(d)
    assert "IGNORE ALL PREVIOUS" not in blob and "bio" not in blob
    shop = next(h for h in d["hits"] if h["site"] == "ExampleShop")
    assert shop["details"]["name"] == "Sample Person"


def test_long_values_are_capped():
    rows = [{"status": "Registered", "site_name": "X", "extra": {"name": "a" * 500}}]
    assert len(userscan.parse_rows(rows, "email")["hits"][0]["details"]["name"]) == userscan.MAX_VALUE


@pytest.mark.parametrize("bad", ["", "-rf", "a b", "x" * 80, "--help", "a/b"])
def test_username_validation(bad):
    with pytest.raises(ValueError):
        userscan.validate_username(bad)


def test_username_strips_at_sign():
    assert userscan.validate_username("@jdoe42") == "jdoe42"


def test_email_scan_ok_reports_errors_and_skips(monkeypatch):
    monkeypatch.setattr(userscan, "_run", lambda flag, value, loud: FIX)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "ok" and "errored" in r["note"] and "skipped" in r["note"]


def test_all_errors_is_error_not_nothing_found(monkeypatch):
    rows = [{"status": "Error", "site_name": "A"}, {"status": "Error", "site_name": "B"}]
    monkeypatch.setattr(userscan, "_run", lambda *a: rows)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "error" and "usable answer" in r["error"]


def test_timeout_is_an_error(monkeypatch):
    def boom(*a):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(userscan, "_run", boom)
    assert userscan.email_scan("sample@example.com")["status"] == "error"


def test_dispatch_email_scan_uses_context_email_not_model_args(monkeypatch):
    seen = {}
    monkeypatch.setattr("privacy_agent.tools.email_scan",
                        lambda email, include_loud=False: seen.setdefault("e", email) and {"status": "ok"})
    dispatch("email_scan", {"email": "attacker@evil.com"}, {"email": "me@example.com"})
    assert seen["e"] == "me@example.com"


def test_dispatch_falls_back_when_user_scanner_missing(monkeypatch):
    monkeypatch.setattr("privacy_agent.tools.email_scan",
                        lambda *a, **k: {"status": "unavailable", "data": {}, "source": "user-scanner"})
    monkeypatch.setattr("privacy_agent.tools.footprint_probe",
                        lambda e: {"status": "ok", "data": {}, "source": "holehe", "note": "x"})
    r = dispatch("email_scan", {}, {"email": "me@example.com"})
    assert r["source"] == "holehe" and "Fallback" in r["note"]


def test_dispatch_username_scan_validates(monkeypatch):
    r = dispatch("username_scan", {"username": "--help"}, {"email": "me@example.com"})
    assert r["status"] == "error"


def test_missing_package_is_unavailable_not_empty(monkeypatch):
    monkeypatch.setattr(userscan, "_installed", lambda: False)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "unavailable" and r["data"] == {}


def test_no_json_error_names_the_scanners_own_message_and_hides_the_value(monkeypatch):
    import subprocess
    from privacy_agent.tools import userscan
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw["env"]
        return subprocess.CompletedProcess(cmd, 1, "", "UnicodeEncodeError for me@example.com in charmap\n")
    monkeypatch.setattr(userscan, "_installed", lambda: True)
    monkeypatch.setattr(userscan.subprocess, "run", fake_run)
    r = userscan.email_scan("me@example.com")
    assert r["status"] == "error"
    assert "UnicodeEncodeError" in r["error"] and "me@example.com" not in r["error"]
    assert seen["env"]["PYTHONUTF8"] == "1"
