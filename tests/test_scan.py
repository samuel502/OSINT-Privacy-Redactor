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


def test_key_status_masks_and_never_shows_full_key():
    from privacy_agent.env import key_status, mask_key
    k = "gsk_ABCDEFGHIJKLMNOP1234"
    s = key_status("groq", environ={"GROQ_API_KEY": k})
    assert "in use" in s and k not in s and s.count("1234") == 1
    assert "No Groq key" in key_status("groq", environ={})
    t = key_status("groq", typed=k, environ={})
    assert "this session" in t and k not in t
    assert mask_key("short") == "••••••••"


def test_ui_scan_always_yields_five_values_and_files_last():
    from privacy_agent.scan import UI_OUTPUTS, ui_scan
    rows = list(ui_scan("both", "a@example.com", "samplehandle", True, dispatch_fn=fake_dispatch,
                        entries=[], routes={}))
    assert all(len(r) == UI_OUTPUTS for r in rows)
    last = rows[-1]
    assert "What was found" in last[1] and isinstance(last[4], list) and all(p.endswith((".md", ".json")) for p in last[4])
    assert all(r[4] is None for r in rows[:-1])


def test_ui_scan_error_row_has_five_values():
    from privacy_agent.scan import UI_OUTPUTS, ui_scan
    rows = list(ui_scan("email", "a@example.com", "", False, dispatch_fn=fake_dispatch, entries=[], routes={}))
    assert len(rows) == 1 and len(rows[0]) == UI_OUTPUTS and rows[0][0].startswith("### Cannot start")
