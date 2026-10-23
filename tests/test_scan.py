"""Offline tests for the Gradio scan path. All data is SYNTHETIC (sample, not live)."""
import pytest

from privacy_agent.schema import result
from privacy_agent.scan import (load_entries, load_routes, render_optout, run_scan,
                                validate_scan_inputs)


def fake_dispatch(name, args, ctx):
    if name == "public_profiles":
        return result("ok", {"sources": {"gravatar": "none", "github": "none"}, "profiles": []}, "gravatar+github")
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


def _merged_with(hit):
    from privacy_agent.merge import merge_findings
    d = {"hits": [hit], "hit_count": 1, "checked": 1, "absent": 0, "errors": 0, "skipped": 0}
    return merge_findings(email_scan=result("ok", d, "user-scanner"))


def test_cards_show_details_category_avatar_and_link():
    from privacy_agent.scan import render_cards_html
    h = {"site": "Etsy", "category": "Shopping", "url": "https://www.etsy.com", "label": "registered",
         "source": "user-scanner", "details": {"name": "Sample Person", "joined": "2021-02-06"},
         "avatar": "https://img.example.com/a.jpg"}
    out = render_cards_html(_merged_with(h))
    assert "Shopping" in out and "Sample Person" in out and "Joined" in out
    assert 'src="https://img.example.com/a.jpg"' in out and 'referrerpolicy="no-referrer"' in out
    assert 'href="https://www.etsy.com"' in out and "not your profile" in out


def test_cards_escape_third_party_text_and_reject_unsafe_links():
    from privacy_agent.scan import render_cards_html
    h = {"site": "<script>alert(1)</script>", "category": "x", "url": "javascript:alert(1)",
         "label": "registered", "source": "user-scanner",
         "details": {"name": "<img src=x onerror=alert(1)>"}, "avatar": "http://insecure.example/a.jpg"}
    out = render_cards_html(_merged_with(h))
    assert "<script>" not in out and "<img src=x" not in out
    assert "javascript:" not in out and "insecure.example" not in out


def test_user_scanner_avatar_is_https_only():
    from privacy_agent.tools.userscan import parse_rows
    rows = [{"status": "Registered", "site_name": "A", "category": "c", "url": "https://a.example", "extra": {},
             "media": {"avatar": "https://cdn.example/p.png"}},
            {"status": "Registered", "site_name": "B", "category": "c", "url": "https://b.example", "extra": {},
             "media": {"avatar": "http://cdn.example/p.png"}}]
    hits = parse_rows(rows, "email")["hits"]
    assert hits[0]["avatar"].startswith("https://") and "avatar" not in hits[1]


def _email_with_usernames(*names):
    hits = [{"site": f"Site{i}", "category": "x", "url": f"https://site{i}.example", "label": "registered",
             "source": "user-scanner", "details": {"username": n}} for i, n in enumerate(names)]
    return result("ok", {"hits": hits, "hit_count": len(hits), "checked": len(hits), "absent": 0,
                         "errors": 0, "skipped": 0}, "user-scanner")


def test_pivot_usernames_filters_dedupes_and_caps():
    from privacy_agent.scan import pivot_usernames
    r = _email_with_usernames("live:bad", "-rf", "Alpha", "alpha", "beta", "gamma", "delta", "typed", "v6zqvxstgrwfyqaw")
    assert pivot_usernames(r, ["typed"]) == ["Alpha", "beta", "gamma"]
    assert pivot_usernames(None) == []


def test_pivot_runs_username_scan_for_found_handles_and_adds_profile_link():
    calls = []

    def disp(name, args, ctx):
        calls.append((name, args.get("username")))
        if name == "public_profiles":
            return result("ok", {"sources": {}, "profiles": []}, "x")
        if name == "email_scan":
            return _email_with_usernames("sample_handle")
        if name == "breach_lookup":
            return result("ok", {"breaches": []}, "x")
        d = {"hits": [{"site": "Site0", "category": "x", "url": "https://site0.example/u/sample_handle",
                       "label": "possible_match", "source": "user-scanner"}],
             "hit_count": 1, "checked": 1, "absent": 0, "errors": 0, "skipped": 0}
        return result("ok", d, "user-scanner")
    b = list(run_scan("email", "a@example.com", "", True, dispatch_fn=disp, routes={}, pivot=True))[-1]["bundle"]
    assert ("username_scan", "sample_handle") in calls
    assert 'href="https://site0.example/u/sample_handle"' in b["report_html"]
    assert "profile page found by username" in b["report_html"]
    calls.clear()
    list(run_scan("email", "a@example.com", "", True, dispatch_fn=disp, routes={}, pivot=False))
    assert not any(n == "username_scan" for n, _ in calls)


def test_pivot_skipped_when_email_scan_failed():
    def disp(name, args, ctx):
        if name == "public_profiles":
            return result("error", source="x", error="down")
        if name == "email_scan":
            return result("error", source="x", error="down")
        if name == "breach_lookup":
            return result("ok", {"breaches": []}, "x")
        raise AssertionError("username_scan must not run")
    list(run_scan("email", "a@example.com", "", True, dispatch_fn=disp, routes={}, pivot=True))


def test_header_stats_profile_links_and_account_row():
    from privacy_agent.scan import render_cards_html
    from privacy_agent.merge import merge_findings
    e = {"hits": [{"site": "Etsy", "category": "Shopping", "url": "https://www.etsy.com", "label": "registered",
                   "source": "user-scanner", "details": {"joined": "2021-02-06 06:28:25",
                                                         "last_profile_update": "2026-09-03"}}],
         "hit_count": 1, "checked": 1, "absent": 0, "errors": 0, "skipped": 0}
    u = {"hits": [{"site": "Etsy", "category": "Shopping", "url": "https://www.etsy.com/people/sample",
                   "label": "possible_match", "source": "user-scanner"}],
         "hit_count": 1, "checked": 1, "absent": 0, "errors": 0, "skipped": 0}
    out = render_cards_html(merge_findings(email_scan=result("ok", e, "user-scanner"),
                                           username_scans=[result("ok", u, "user-scanner")]))
    assert "2021-02-06" in out and "2026-09-03" in out
    assert "Profile links" in out and 'href="https://www.etsy.com/people/sample"' in out
    assert "Registered with your email" in out


def test_header_says_not_reported_when_no_dates():
    from privacy_agent.scan import render_cards_html
    out = render_cards_html(_merged_with({"site": "Canva", "category": "c", "url": "https://canva.com",
                                          "label": "registered", "source": "user-scanner"}))
    assert out.count("not reported by any site") == 2


def test_looks_generated_flags_random_handles_only():
    from privacy_agent.scan import looks_generated
    assert looks_generated("v6zqvxstgrwfyqaw")
    assert not looks_generated("samuel-nadel-526148215") and not looks_generated("Samuel90388")
    assert not looks_generated("samuel502")


def test_pivot_prefers_public_profile_handles():
    from privacy_agent.scan import pivot_usernames
    prof = result("ok", {"profiles": [{"details": {"username": "owner_chosen"}}]}, "x")
    assert pivot_usernames(_email_with_usernames("other"), profiles_res=prof)[0] == "owner_chosen"


def _agent_dispatch(name, args, ctx):
    if name == "email_scan":
        return fake_dispatch("email_scan", args, ctx)
    if name == "breach_lookup":
        return fake_dispatch("breach_lookup", args, ctx)
    return result("ok", {"matches": []}, "fake")


def test_ui_agent_builds_cards_from_tool_results_and_shows_summary_as_markdown_tab():
    from privacy_agent.llm import ModelTurn, ScriptedBackend, ToolCall
    from privacy_agent.scan import UI_OUTPUTS, ui_agent
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("email_scan"), ToolCall("breach_lookup")]),
                               ModelTurn(text="**What matters most:** one account and one breach.")])
    rows = list(ui_agent("a@example.com", "other", backend, dispatch_fn=_agent_dispatch, entries=[], routes={}))
    assert all(len(r) == UI_OUTPUTS for r in rows)
    trace, report, checklist, summary, files = rows[-1]
    assert "Etsy" in report and "SampleBreach" in report          # cards come from the tool results
    assert summary.startswith("**What matters most:**") and "<" not in summary
    assert isinstance(files, list) and all(r[4] is None for r in rows[:-1])
    assert "a@example.com" not in backend.user and "a@example.com" not in backend.system


def test_ui_agent_notes_when_the_step_limit_cut_the_answer_short():
    from privacy_agent.llm import ModelTurn, ScriptedBackend, ToolCall
    from privacy_agent.scan import ui_agent
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("breach_lookup")]), ModelTurn(text="partial answer")])
    rows = list(ui_agent("a@example.com", "other", backend, max_steps=2, dispatch_fn=_agent_dispatch,
                         entries=[], routes={}))
    assert "step limit" in rows[-1][3]


def test_ui_agent_bad_email_and_backend_error_are_shown_not_raised():
    from privacy_agent.llm import ModelTurn, ScriptedBackend
    from privacy_agent.scan import ui_agent
    rows = list(ui_agent("nope", "other", ScriptedBackend([]), dispatch_fn=_agent_dispatch, entries=[], routes={}))
    assert rows[-1][0].startswith("**Error:**")
    rows = list(ui_agent("a@example.com", "other", ScriptedBackend([]), dispatch_fn=_agent_dispatch,
                         entries=[], routes={}))
    assert "failed" in rows[-1][1].lower()


def test_prompt_forbids_invented_links_and_account_deletion():
    from privacy_agent.agent import SYSTEM_PROMPT
    assert "ONLY if it is in a tool result" in SYSTEM_PROMPT
    assert "Do not tell the user to delete" in SYSTEM_PROMPT and "under 200 words" in SYSTEM_PROMPT


def test_ungrounded_links_are_flagged_and_grounded_ones_are_not():
    from privacy_agent.scan import ungrounded_links
    events = [{"type": "observation", "name": "search_playbooks",
               "result": {"data": {"x": "https://x.com/settings/deactivate"}}}]
    text = "Use https://x.com/settings/deactivate. Or write to support@8fit.com, see https://www.etsy.com/delete."
    assert ungrounded_links(text, events) == ["support@8fit.com", "https://www.etsy.com/delete"]


def test_ui_agent_warns_about_invented_links():
    from privacy_agent.llm import ModelTurn, ScriptedBackend, ToolCall
    from privacy_agent.scan import ui_agent
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("breach_lookup")]),
                               ModelTurn(text="Email support@8fit.com to erase it.")])
    rows = list(ui_agent("a@example.com", "other", backend, dispatch_fn=_agent_dispatch, entries=[], routes={}))
    assert "Warning" in rows[-1][3] and "support@8fit.com" in rows[-1][3]


def test_optout_cards_show_full_steps_and_never_truncate():
    from privacy_agent.scan import render_optout_html
    long = "Step " + "x" * 400 + " END-OF-STEPS"
    out = render_optout_html([{"category": "lookup_service", "name": "Site", "steps_summary": long,
                               "opt_out_url": "https://site.example/optout", "verified": False,
                               "requires_email_confirmation": True, "needs_captcha": True}])
    assert "END-OF-STEPS" in out and "researched, not tested" in out
    assert "confirm by email" in out and "bot check: you click it" in out
    assert 'href="https://site.example/optout"' in out


def test_optout_card_for_email_route_has_copyable_draft_without_real_address():
    from privacy_agent.scan import render_optout_html
    out = render_optout_html([{"category": "lookup_service", "name": "Epieos", "steps_summary": "No form.",
                               "opt_out_email": "contact@epieos.com", "verified": True, "last_verified": "2026-09-12"}])
    assert "contact@epieos.com" in out and "Draft email" in out and "[YOUR EMAIL ADDRESS]" in out
    assert "verified 2026-09-12" in out


def test_optout_html_escapes_registry_text():
    from privacy_agent.scan import render_optout_html
    out = render_optout_html([{"category": "lookup_service", "name": "<b>x</b>", "steps_summary": "<script>1</script>",
                               "opt_out_url": "javascript:alert(1)"}])
    assert "<script>" not in out and "javascript:" not in out


def test_markdown_optout_no_longer_cuts_steps():
    from privacy_agent.scan import render_optout
    text = "a" * 300 + "ENDMARK"
    assert "ENDMARK" in render_optout([{"category": "lookup_service", "name": "S", "steps_summary": text}])
