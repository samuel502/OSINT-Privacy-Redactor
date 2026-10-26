from privacy_agent.agent import format_event, run_agent
from privacy_agent.llm import ModelTurn, ScriptedBackend, ToolCall
from privacy_agent.schema import result


def fake_dispatch_factory(log):
    def fake(name, args, ctx):
        log.append((name, args, ctx["email"]))
        return result("ok", {"echo": name}, "fake")
    return fake


def test_loop_runs_tools_then_finishes_and_feeds_observations_back():
    log = []
    backend = ScriptedBackend([
        ModelTurn(calls=[ToolCall("email_scan"), ToolCall("breach_lookup")]),
        ModelTurn(calls=[ToolCall("search_playbooks", {"query": "github.com"})]),
        ModelTurn(text="Plan: delete GitHub."),
    ])
    events = list(run_agent("me@example.com", "gdpr", backend, dispatch_fn=fake_dispatch_factory(log)))
    assert [e["type"] for e in events].count("tool_call") == 3
    assert events[-1] == {"type": "final", "step": 3, "text": "Plan: delete GitHub."}
    assert len(backend.seen) == 2 and backend.seen[0][0][1]["data"]["echo"] == "email_scan"


def test_email_is_pinned_and_not_sent_to_the_model():
    log = []
    backend = ScriptedBackend([
        ModelTurn(calls=[ToolCall("email_scan", {"email": "victim@other.com"})]),
        ModelTurn(text="done"),
    ])
    list(run_agent("me@example.com", "gdpr", backend, dispatch_fn=fake_dispatch_factory(log)))
    assert log[0][2] == "me@example.com"
    assert "me@example.com" not in backend.user and "me@example.com" not in backend.system


def test_repeated_identical_call_is_cached():
    log = []
    backend = ScriptedBackend([
        ModelTurn(calls=[ToolCall("breach_lookup")]),
        ModelTurn(calls=[ToolCall("breach_lookup")]),
        ModelTurn(text="ok"),
    ])
    list(run_agent("me@example.com", "gdpr", backend, dispatch_fn=fake_dispatch_factory(log)))
    assert len(log) == 1


def test_step_limit_stops_runaway_model():
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("search_playbooks", {"query": str(i)})]) for i in range(20)])
    events = list(run_agent("me@example.com", "gdpr", backend, max_steps=3,
                            dispatch_fn=fake_dispatch_factory([])))
    assert events[-1]["type"] == "final" and events[-1]["truncated"] is True


def test_backend_failure_becomes_error_event():
    events = list(run_agent("me@example.com", "gdpr", ScriptedBackend([])))
    assert events[-1]["type"] == "error"


def test_invalid_email_rejected_before_anything_runs():
    import pytest
    with pytest.raises(ValueError):
        list(run_agent("--help", "gdpr", ScriptedBackend([])))


def test_format_event_truncates_long_observations():
    big = result("ok", {"x": "y" * 5000})
    out = format_event({"type": "observation", "name": "t", "result": big})
    assert "truncated" in out and len(out) < 2000


# ---- Groq backend, tested with a fake client (no network) ----
from types import SimpleNamespace as NS

from privacy_agent.llm import GroqBackend, LLMError, make_backend


class _FakeGroq:
    def __init__(self, messages_out):
        self.out, self.calls = list(messages_out), []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.calls.append({"messages": list(kw["messages"]), "tools": kw["tools"]})
        return NS(choices=[NS(message=self.out.pop(0))])


def _tc(id_, name, args="{}"):
    return NS(id=id_, function=NS(name=name, arguments=args))


def test_groq_backend_roundtrips_tool_calls_and_truncates_observations():
    client = _FakeGroq([NS(content=None, tool_calls=[_tc("c1", "breach_lookup")]),
                        NS(content="All done.", tool_calls=None)])
    events = list(run_agent("me@example.com", "gdpr", GroqBackend(client=client),
                            dispatch_fn=lambda n, a, c: result("ok", {"big": "x" * 9000}, "fake")))
    assert events[-1]["text"] == "All done."
    second = client.calls[1]["messages"]
    tool_msgs = [m for m in second if m["role"] == "tool"]
    assert tool_msgs and tool_msgs[-1]["tool_call_id"] == "c1"
    assert any(m["role"] == "assistant" and m.get("tool_calls") and m["tool_calls"][0]["id"] == "c1" for m in second)
    assert len(tool_msgs[-1]["content"]) < 4100 and "truncated" in tool_msgs[-1]["content"]
    assert all(t["type"] == "function" and "parameters" in t["function"] for t in client.calls[0]["tools"])
    assert "me@example.com" not in str(client.calls[0]["messages"])


def test_groq_bad_tool_arguments_become_empty_args():
    client = _FakeGroq([NS(content="", tool_calls=[_tc("c1", "search_playbooks", "{not json")])])
    b = GroqBackend(client=client)
    b.start("s", "u")
    assert b.generate().calls[0].args == {}


def test_make_backend_selection(monkeypatch):
    import pytest
    for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(LLMError, match="API key"):
        make_backend()
    with pytest.raises(LLMError, match="Groq"):
        make_backend("groq")
    with pytest.raises(LLMError, match="Unknown provider"):
        make_backend("nope")


def test_last_step_forces_a_final_answer_instead_of_stopping_silently():
    turns = [ModelTurn(calls=[ToolCall("search_playbooks", {"query": str(i)})]) for i in range(2)]
    turns.append(ModelTurn(text="Plan from what I have."))
    backend = ScriptedBackend(turns)
    events = list(run_agent("me@example.com", "gdpr", backend, max_steps=3,
                            dispatch_fn=fake_dispatch_factory([])))
    assert events[-1]["type"] == "final" and events[-1]["text"] == "Plan from what I have."
    assert events[-1].get("forced") is True
    assert backend.last_allow_tools is False and backend.notes


def test_forced_turn_that_still_calls_tools_ends_honestly():
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("breach_lookup")]) for _ in range(5)])
    events = list(run_agent("me@example.com", "gdpr", backend, max_steps=2,
                            dispatch_fn=fake_dispatch_factory([])))
    assert events[-1]["type"] == "final" and events[-1]["truncated"] is True


def test_facts_note_is_computed_in_code_and_fed_back():
    from privacy_agent.agent import facts_note
    esc = result("ok", {"hits": [{"site": "A", "category": "c", "url": "https://a.example", "label": "registered",
                                  "source": "s"}], "hit_count": 1, "checked": 3, "absent": 2, "errors": 4,
                         "skipped": 5}, "user-scanner")
    br = result("ok", {"breaches": [{"name": "SampleBreach"}]}, "x")
    cache = {("email_scan", "{}"): esc, ("breach_lookup", "{}"): br}
    f = facts_note(cache)
    assert "confirmed accounts: 1" in f and "4 errored, 5 skipped" in f and "SampleBreach" in f
    assert facts_note({}) == ""


def test_run_agent_gives_the_model_the_facts_after_tools_run():
    backend = ScriptedBackend([ModelTurn(calls=[ToolCall("breach_lookup")]), ModelTurn(text="done")])

    def disp(name, args, ctx):
        return result("ok", {"breaches": [{"name": "SampleBreach"}]}, "x")
    list(run_agent("me@example.com", "gdpr", backend, dispatch_fn=disp))
    assert any("SampleBreach" in n and "FACTS" in n for n in backend.notes)
    
def test_undeclared_tool_is_refused_in_code():
    log = []
    backend = ScriptedBackend([
        ModelTurn(calls=[ToolCall("footprint_probe"), ToolCall("made_up_tool")]),
        ModelTurn(text="done"),
    ])
    events = list(run_agent("me@example.com", "gdpr", backend, dispatch_fn=fake_dispatch_factory(log)))
    assert log == []  # the dispatcher was never reached
    obs = [e for e in events if e["type"] == "observation"]
    assert [o["result"]["status"] for o in obs] == ["error", "error"]
