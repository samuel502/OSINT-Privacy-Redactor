"""Offline tests for email_scan / username_scan. Fixture data is SYNTHETIC (sample, not live)."""
import json
import os
import pathlib
import subprocess
import sys
import threading
import time

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
    monkeypatch.setattr(userscan, "_run", lambda flag, value, loud, **kw: FIX)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "ok" and "errored" in r["note"] and "skipped" in r["note"]


def test_all_errors_is_error_not_nothing_found(monkeypatch):
    rows = [{"status": "Error", "site_name": "A"}, {"status": "Error", "site_name": "B"}]
    monkeypatch.setattr(userscan, "_run", lambda *a, **k: rows)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "error" and "usable answer" in r["error"]


def test_timeout_is_timed_out_with_counts_not_nothing_found(monkeypatch):
    def boom(*a, **k):
        raise userscan.ScanTimeout(120, {"found": 2, "absent": 40, "errors": 3, "skipped": 5})
    monkeypatch.setattr(userscan, "_run", boom)
    r = userscan.email_scan("sample@example.com")
    assert r["status"] == "error" and r["data"]["timed_out"] is True
    assert r["data"]["checked"] == 42 and r["data"]["skipped"] == 5
    assert r["error"].startswith("Timed out after 120s: 42 sites answered (2 found), 5 skipped, 3 errored")
    assert "NOT checked" in r["error"]


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

    def fake_run_capped(cmd, timeout, env=None, progress=None, cancel=None):
        seen["env"], seen["cmd"], seen["timeout"] = env, cmd, timeout
        return 1, ["UnicodeEncodeError for me@example.com in charmap\n"]
    monkeypatch.setattr(userscan, "_installed", lambda: True)
    monkeypatch.setattr(userscan, "run_capped", fake_run_capped)
    r = userscan.email_scan("me@example.com")
    assert r["status"] == "error"
    assert "UnicodeEncodeError" in r["error"] and "me@example.com" not in r["error"]
    assert seen["env"]["PYTHONUTF8"] == "1" and seen["env"]["PYTHONUNBUFFERED"] == "1"
    assert "--all" in seen["cmd"] and seen["timeout"] == userscan.TIMEOUT_S == 120


# ---------------------------------------------------------------- process control (real child processes, no network)

def _alive(pid: int) -> bool:
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        try:  # a killed child can linger as a zombie until reaped; that is not running
            with open(f"/proc/{pid}/stat") as fh:
                return fh.read().split()[2] != "Z"
        except OSError:
            return True
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
    return str(pid) in out


def test_timeout_kills_the_scanner_and_every_child_and_keeps_the_counts(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    parent = (
        "import subprocess, sys, time\n"
        f"g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(g.pid))\n"
        "print('  [\\u2714] SiteA: Registered', flush=True)\n"
        "print('  [~] SiteB: Skipped', flush=True)\n"
        "print('[!] New version available', flush=True)\n"
        "time.sleep(60)\n"
    )
    start = time.monotonic()
    with pytest.raises(userscan.ScanTimeout) as e:
        userscan.run_capped([sys.executable, "-c", parent], timeout=3,
                            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    assert time.monotonic() - start < 20
    assert e.value.progress == {"found": 1, "absent": 0, "errors": 0, "skipped": 1}  # column-0 notice not counted
    gpid = int(pidfile.read_text())
    deadline = time.monotonic() + 10
    while _alive(gpid) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _alive(gpid), "the scanner's child process kept running after the timeout"


def test_stdin_is_closed_so_an_update_prompt_cannot_hang_the_scan():
    child = "try:\n    input('update? (y/n): ')\nexcept EOFError:\n    print('eof')\n"
    code, tail = userscan.run_capped([sys.executable, "-c", child], timeout=20)
    assert code == 0 and any("eof" in line for line in tail)


def test_cancel_stops_the_scanner():
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    with pytest.raises(userscan.ScanTimeout) as e:
        userscan.run_capped([sys.executable, "-c", "import time; time.sleep(60)"], timeout=60, cancel=cancel)
    assert e.value.cancelled is True


def test_dispatch_passes_time_limit_progress_and_cancel_to_the_scanner(monkeypatch):
    seen = {}
    monkeypatch.setattr("privacy_agent.tools.username_scan", lambda u, **kw: seen.update(kw) or {"status": "ok"})
    ev, prog = threading.Event(), {}
    dispatch("username_scan", {"username": "sample"}, {"email": "", "timeout": 42, "progress": prog, "cancel": ev})
    assert seen == {"timeout": 42, "progress": prog, "cancel": ev}
