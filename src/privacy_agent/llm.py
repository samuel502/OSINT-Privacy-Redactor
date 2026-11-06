"""LLM backend (Groq). The agent only needs three methods: start / generate / add_tool_results.

ScriptedBackend replays canned turns for tests, so tests need no API key or quota.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from .tools import DECLARATIONS


class LLMError(RuntimeError):
    pass


@dataclass
class ToolCall:
    name: str
    args: dict = field(default_factory=dict)
    id: str = ""


@dataclass
class ModelTurn:
    text: str = ""
    calls: list = field(default_factory=list)


def _openai_tools(declarations):
    """Convert our declarations to OpenAI-style tool specs (used by Groq)."""
    return [{"type": "function",
             "function": {"name": d["name"], "description": d["description"],
                          "parameters": d.get("parameters") or {"type": "object", "properties": {}}}}
            for d in declarations]


class GroqBackend:
    """Groq's OpenAI-compatible chat API with tool calling. Free tier: ~30 req/min, small token/min cap,
    so observations sent back to the model are truncated."""
    MAX_OBS_CHARS = 4000

    def __init__(self, api_key: str | None = None, model: str | None = None, declarations=None, client=None):
        if client is None:
            key = api_key or os.environ.get("GROQ_API_KEY")
            if not key:
                raise LLMError("No Groq API key. Add GROQ_API_KEY to Colab Secrets.")
            from groq import Groq
            client = Groq(api_key=key)
        self.client = client
        # Check console.groq.com/docs/models; model names rotate. Override with GROQ_MODEL.
        self.model = model or os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
        self.tools = _openai_tools(declarations or DECLARATIONS)
        self.messages: list = []
        self._reasoning = True

    def start(self, system: str, user: str) -> None:
        self.messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def _kwargs(self):
        # gpt-oss burns tokens in the reasoning field; Groq's free TPM cap is small.
        return ({"reasoning_effort": os.environ.get("GROQ_REASONING_EFFORT", "low")}
                if self._reasoning else {})

    def add_user_note(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def _call(self, allow_tools: bool = True):
        for attempt in range(3):
            try:
                return self.client.chat.completions.create(
                    model=self.model, messages=self.messages, tools=self.tools,
                    tool_choice="auto" if allow_tools else "none", temperature=0, **self._kwargs())
            except TypeError:  # model rejects reasoning_effort
                self._reasoning = False
                continue
            except Exception as e:  # noqa: BLE001
                status = getattr(e, "status_code", None)
                if (status == 429 or type(e).__name__ == "RateLimitError") and attempt < 2:
                    time.sleep(15 * (attempt + 1))
                    continue
                if "tool_use_failed" in str(e) and attempt < 2:  # malformed tool call; retry
                    continue
                if status == 429 or type(e).__name__ == "RateLimitError":
                    raise LLMError("Groq rate limit (429). Wait a minute or check console.groq.com limits.") from e
                raise LLMError(f"Groq API error ({type(e).__name__}): {e}") from e

    def generate(self, allow_tools: bool = True) -> ModelTurn:
        resp = self._call(allow_tools)
        if not getattr(resp, "choices", None):
            raise LLMError("Groq returned no choices.")
        msg = resp.choices[0].message
        tool_calls = getattr(msg, "tool_calls", None) or []
        assistant = {"role": "assistant", "content": msg.content or ""}
        if tool_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}}
                for tc in tool_calls]
        self.messages.append(assistant)
        calls = []
        for tc in tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(tc.function.name, args if isinstance(args, dict) else {}, tc.id))
        return ModelTurn((msg.content or "").strip(), calls)

    def add_tool_results(self, results) -> None:
        for call, obs in results:
            if isinstance(obs, str):  # already marked and truncated by the agent; keep the end marker
                self.messages.append({"role": "tool", "tool_call_id": call.id, "content": obs})
                continue
            body = json.dumps(obs, default=str)
            if len(body) > self.MAX_OBS_CHARS:
                body = body[: self.MAX_OBS_CHARS] + "...(truncated)"
            self.messages.append({"role": "tool", "tool_call_id": call.id, "content": body})


def make_backend(provider: str | None = "groq", api_key: str | None = None, model: str | None = None):
    """provider: 'groq' (the only backend). The key comes from Colab Secrets via app.launch()."""
    provider = (provider or "groq").lower()
    if provider == "groq":
        return GroqBackend(api_key=api_key, model=model)
    raise LLMError(f"Unknown provider {provider!r}; use 'groq'.")


class ScriptedBackend:
    """Replays a fixed list of ModelTurn objects. For tests only; it is not an LLM."""

    def __init__(self, turns):
        self.turns, self.i, self.seen, self.system, self.user = list(turns), 0, [], "", ""

    def start(self, system: str, user: str) -> None:
        self.system, self.user = system, user

    def add_user_note(self, text: str) -> None:
        self.notes = getattr(self, "notes", []) + [text]

    def generate(self, allow_tools: bool = True) -> ModelTurn:
        self.last_allow_tools = allow_tools
        if self.i >= len(self.turns):
            raise LLMError("ScriptedBackend ran out of turns.")
        turn = self.turns[self.i]
        self.i += 1
        return turn

    def add_tool_results(self, results) -> None:
        self.seen.append(results)
