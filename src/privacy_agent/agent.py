"""The agent loop: the model picks tools, Python runs them, observations go back, repeat."""
from __future__ import annotations

import json

from .llm import LLMError
from .schema import validate_email
from .tools import dispatch

SYSTEM_PROMPT = """You are a privacy-audit assistant. The user is auditing THEIR OWN email address and wants \
(1) to see what is publicly tied to it and (2) a concrete plan to remove or reduce it.

You choose which tools to call; you do not know the email address and never need to. Work like this:
- Start by discovering exposure with footprint_probe and breach_lookup (neither takes arguments).
- For each confirmed account, prefer ONE batched search_playbooks call with queries=[all domains].
- search_playbooks also covers lookup_service sites (emailosint.org, fingerprint.to, epieos.com and
  similar) and browser_config entries. Include those in the same batch when relevant.
- Use draft_erasure_request only when there is no verified playbook, or when an emailed legal request is the better route.
- Prioritise: services involved in breaches first, then accounts with the easiest removal.

Rules:
- Base every claim on tool observations. Never invent accounts, URLs, or steps.
- A tool status of "unavailable" or "error" means that check did NOT happen. Say so; never present it as "nothing found".
- Absence of results is not proof of absence. Say this once, briefly.
- footprint_probe reports rate_limited_or_unchecked sites: those were NOT checked. State how many, and suggest re-running later or without a VPN. Do not call footprint_probe twice.
- If a playbook has needs_captcha=true, tell the user they must solve the CAPTCHA and click the emailed confirmation link themselves.
- If a playbook has verified=false, tell the user to confirm the steps on the service's own site.
- Do not call the same tool with the same arguments twice. Stop calling tools once you have enough.

Final answer: a short prioritised checklist (what to do, link, effort), then a "Could not check" list for anything unavailable or failed."""


def run_agent(email: str, jurisdiction: str, backend, max_steps: int = 14,
              dispatch_fn=dispatch, full_name: str | None = None):
    """Generator of event dicts: model / tool_call / observation / final / error."""
    email = validate_email(email)
    ctx = {"email": email, "jurisdiction": jurisdiction, "full_name": full_name}
    cache: dict = {}
    try:
        backend.start(SYSTEM_PROMPT,
                      f"Audit my own email address. My legal jurisdiction: {jurisdiction}. "
                      "Find my exposure and give me a removal plan.")
        for step in range(1, max_steps + 1):
            turn = backend.generate()
            if turn.text and turn.calls:
                yield {"type": "model", "step": step, "text": turn.text}
            if not turn.calls:
                yield {"type": "final", "step": step, "text": turn.text or "(The model returned no answer.)"}
                return
            results = []
            for call in turn.calls:
                yield {"type": "tool_call", "step": step, "name": call.name, "args": call.args}
                key = (call.name, json.dumps(call.args, sort_keys=True, default=str))
                if key in cache:
                    obs = {**cache[key], "note": "Repeated call: returning cached result."}
                else:
                    obs = dispatch_fn(call.name, call.args, ctx)
                    cache[key] = obs
                yield {"type": "observation", "step": step, "name": call.name, "result": obs}
                results.append((call, obs))
            backend.add_tool_results(results)
        yield {"type": "final", "step": max_steps, "truncated": True,
               "text": f"Stopped after {max_steps} steps without a final answer. Raise max_steps or retry."}
    except LLMError as e:
        yield {"type": "error", "text": str(e)}


def format_event(ev: dict, max_chars: int = 1500) -> str:
    t = ev["type"]
    if t == "model":
        return f"**Step {ev['step']} - model:** {ev['text']}"
    if t == "tool_call":
        args = json.dumps(ev["args"]) if ev["args"] else "(no arguments)"
        return f"**Step {ev['step']} - calls `{ev['name']}`** {args}"
    if t == "observation":
        body = json.dumps(ev["result"], indent=2, default=str)
        if len(body) > max_chars:
            body = body[:max_chars] + "\n... (truncated)"
        return f"**Observation from `{ev['name']}`** (status: {ev['result']['status']})\n```json\n{body}\n```"
    if t == "final":
        return f"**Finished at step {ev['step']}.**"
    return f"**Error:** {ev['text']}"
