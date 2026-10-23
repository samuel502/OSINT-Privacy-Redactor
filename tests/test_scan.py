"""Offline tests for the Gradio scan path. All data is SYNTHETIC (sample, not live)."""
import pytest

from privacy_agent.schema import result
from privacy_agent.scan import (load_entries, load_routes, render_optout, run_scan,
                                validate_scan_inputs)


def fake_dispatch(name, args, ctx):
    if name == "email_scan":
        return result("ok", {"hits": [{"site": "Etsy", "category": "shopping", "url": "https://www.etsy.com",
                                       "label": "registered", "source": "user-scanner"}],
                             "hit_count": 1, "checked": 5, "absent": 4, "errors": 2, "skipped": 0}, "user-scanner")
    if name == "breach_lookup":
        return result("ok", {"breach_count": 1, "breaches": [{"name": "SampleBreach"}]}, "xposedornot.com")
    if name == "username_scan":
        return result("ok", {"hits": [{"site": "Medium", "category": "blog", "url": "https://medium.com/@sample",
                                       "label": "possible_match", "source": "user-scanner"}],
                             "hit_count": 1, "checked": 5, "absent": 4, "errors": 0, "skipped": 0}, "user-scanner")
    raise AssertionError(name)


def _bundle(mode, **kw):
    evs = list(run_scan(mode, kw.get("email", "a@example.com"), kw.get("username", "samplehandle"), True,
                        dispatch_fn=fake_dispatch, routes={}))
    assert evs[-1]["type"] == "bundle"
    return evs[-1]["bundle"]


def test_ownership_box_is_required():
    with pytest.raises(ValueError, match="own"):
        validate_scan_inputs("email", "a@example.com", "", False)


def test_bad_mode_email_and_username_rejected():
    with pytest.raises(ValueError):
        validate_scan_inputs("nope", "a@example.com", "", True)
    with pytest.raises(ValueError):
        validate_scan_inputs("email", "not-an-email", "", True)
    with pytest.raises(ValueError):
        validate_scan_inputs("username", "", "", True)
    with pytest.raises(ValueError):
        validate_scan_inputs("username", "", "-rf", True)


def test_email_mode_runs_email_and_breach_only():
    b = _bundle("email")
    assert b["merged"]["summary"]["confirmed"] == 1 and b["merged"]["summary"]["possible"] == 0
    assert b["raw"]["username_scans"] == []


def test_username_mode_gives_possible_matches_only():
    b = _bundle("username")
    assert b["merged"]["summary"]["confirmed"] == 0 and b["merged"]["summary"]["possible"] == 1
    assert "Possible matches" in b["report_md"] and "### Confirmed accounts" not in b["report_md"]


def test_both_mode_labels_and_caveats():
    md = _bundle("both")["report_md"]
    assert "### Confirmed accounts" in md and "### Possible matches" in md and "SampleBreach" in md
    assert "may belong to someone else" in md


def test_failed_check_is_not_shown_as_nothing_found():
    def bad(name, args, ctx):
        return result("error", source="x", error="Timed out") if name == "email_scan" else fake_dispatch(name, args, ctx)
    b = list(run_scan("email", "a@example.com", "", True, dispatch_fn=bad, routes={}))[-1]["bundle"]
    assert "Could not check" in b["report_md"] and "Timed out" in b["report_md"]
    assert "None found among the sites that answered" not in b["report_md"]


def test_email_is_not_in_step_text_for_model_free_path_json_raw_only():
    evs = list(run_scan("email", "a@example.com", "", True, dispatch_fn=fake_dispatch, routes={}))
    assert all("a@example.com" not in e["text"] for e in evs if e["type"] == "step")


def test_optout_checklist_labels_unverified_and_groups():
    md = render_optout(load_entries())
    assert "researched, not tested" in md and "verified" in md
    assert "Opt out of OSINT lookup sites" in md


def test_registry_routes_load():
    assert "emailosint.org" in load_routes()
