"""The agent loop: the model picks tools, Python runs them, observations go back, repeat."""
from __future__ import annotations

import json

from .llm import LLMError
from .schema import validate_email
from .tools import dispatch

SYSTEM_PROMPT = """You are a privacy-audit assistant. The user is checking THEIR OWN email address. They want \
(1) to know what is findable about it (accounts, breaches) and (2) which OSINT lookup sites expose it and \
how to opt out of them.

You choose which tools to call; you do not know the email address and never need to. Work like this:
- Start by discovering exposure with email_scan and breach_lookup (neither takes arguments).
- If email_scan details show a real-looking username, you may run username_scan on it. Treat every username hit as a POSSIBLE match, never as confirmed.
- Call search_playbooks ONCE with queries=[...] to find opt-out routes. It covers OSINT lookup sites (emailosint.org, fingerprint.to, epieos.com and similar) and any confirmed account domains you want to check.
- Use draft_erasure_request only for a service that appeared in a breach, or when an emailed legal request is the best route.
- Do not call the same tool with the same arguments twice. Stop calling tools once you have enough.

Rules:
- Base every claim on tool observations. Never invent accounts, steps, web links or email addresses. A link or contact address may appear in your answer ONLY if it is in a tool result.
- Do not tell the user to delete or deactivate their accounts. That is outside this tool's purpose.
- A tool status of "unavailable" or "error" means that check did NOT happen. Say so; never present it as "nothing found".
- email_scan reports how many sites errored or were skipped: those were NOT checked. State the numbers once.
- If a playbook has needs_captcha=true, say the user must solve the CAPTCHA and click the emailed confirmation link themselves.
- If a playbook has verified=false, say it is researched but not tested and to confirm the steps on the site.

Final answer: plain language, under 200 words, no tables, no code blocks. Three short parts:
1. What matters most: 2 to 4 sentences with the counts and anything notable (breaches, usernames found).
2. What to do next: a numbered list of at most 5 steps. Each step uses only a route that came from search_playbooks or a draft you produced, and says whether it is verified.
3. Could not check: one line with the counts of errors and skipped sites.
Do NOT list every account; the app already shows them as cards."""


def run_agent(email: str, jurisdiction: str, backend, max_steps: int = 14,
              dispatch_fn=dispatch, full_name: str | None = None):
    """Generator of event dicts: model / tool_call / observation / final / error."""
    email = validate_email(email)
    ctx = {"email": email, "jurisdiction": jurisdiction, "full_name": full_name}
    cache: dict = {}
    try:
        backend.start(SYSTEM_PROMPT,
                      f"Check my own email address. My legal jurisdiction: {jurisdiction}. "
                      "Find what is findable about it and which OSINT lookup sites I should opt out of.")
        for step in range(1, max_steps + 1):
            last = step == max_steps
            if last and max_steps > 1:
                # Out of budget: ask for the answer now, from what the tools already returned.
                backend.add_user_note(
                    "Tool budget used up. Do not call any more tools. Write the final answer now "
                    "from the observations you already have, and list anything you could not check.")
            turn = backend.generate(allow_tools=not (last and max_steps > 1))
            if last and turn.calls:
                turn.calls = []  # tools were disallowed; ignore any attempted call
            if turn.text and turn.calls:
                yield {"type": "model", "step": step, "text": turn.text}
            if not turn.calls:
                if last and not turn.text:
                    break
                yield {"type": "final", "step": step, "text": turn.text or "(The model returned no answer.)",
                       **({"forced": True} if last else {})}
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
