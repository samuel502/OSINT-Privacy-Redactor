"""The agent loop: the model picks tools, Python runs them, observations go back, repeat."""
from __future__ import annotations

import json

from .llm import LLMError
from .schema import result, validate_email
from .tools import DECLARATIONS, dispatch

 # The only tools the model may call. Anything else is refused in code, whatever the prompt says.
 ALLOWED_TOOLS = {d["name"] for d in DECLARATIONS}

SYSTEM_PROMPT = """You are a privacy-audit assistant. The user is checking THEIR OWN email address. They want \
(1) to know what is findable about it (accounts, breaches) and (2) which OSINT lookup sites expose it and \
how to opt out of them.

You choose which tools to call; you do not know the email address and never need to. Work like this:
- Start by discovering exposure with email_scan and breach_lookup (neither takes arguments).
- If email_scan details show a real-looking username, you may run username_scan on it. Treat every username hit as a POSSIBLE match, never as confirmed.
- Call search_playbooks ONCE with queries=[...] to find opt-out routes. It covers OSINT lookup sites (emailosint.org, fingerprint.to, epieos.com and similar) and any confirmed account domains you want to check.
- Use draft_erasure_request ONLY for a service that appeared in a breach. Never draft requests for the accounts email_scan found.
- Do not call the same tool with the same arguments twice. Stop calling tools once you have enough.

Rules:
- Base every claim on tool observations. Never invent accounts, steps, web links or email addresses. A link or contact address may appear in your answer ONLY if it is in a tool result.
- Do not tell the user to delete, close or deactivate their accounts. That is outside this tool's purpose.
- Say a route is "verified" ONLY if its search_playbooks result has verified=true. Otherwise say "researched, not tested".
- Services that appeared in a breach have no playbook. Do not say a removal form exists for them. You may offer a draft erasure email (draft_erasure_request) and say it is a draft the user sends themselves.
- After each tool round you receive a FACTS note computed in code. Use its numbers exactly; never contradict it.
- A tool status of "unavailable" or "error" means that check did NOT happen. Say so; never present it as "nothing found".
- email_scan reports how many sites errored or were skipped: those were NOT checked. State the numbers once.
- If a playbook has needs_captcha=true, say the user must solve the CAPTCHA and click the emailed confirmation link themselves.
- If a playbook has verified=false, say it is researched but not tested and to confirm the steps on the site.

Final answer: plain language, under 200 words, no tables, no code blocks. Three short parts:
1. What matters most: 2 to 4 sentences with the counts from the FACTS note and anything notable (breaches, usernames found).
2. What to do next: a numbered list of at most 4 steps, only these kinds:
   - Opt out of the OSINT lookup sites: tell the user to open the "Opt-out checklist" tab, and name up to 3 sites from your search_playbooks results with whether each is verified or researched, not tested.
   - If you called draft_erasure_request for a breached service, say which service. The app prints every draft under your answer; the user sends them themselves. Draft one for EACH breached service.
   - For a site whose route is a written email, say its card in the "Opt-out checklist" tab has a copy-paste draft. Do not say "the draft below" for it.
   - Re-run later (without a VPN) for the sites that errored.
   Never tell the user to send requests to, delete, or close the accounts email_scan found, and never mention a draft you did not produce.
3. Could not check: one line with the counts of errors and skipped sites.
Do NOT list every account; the app already shows them as cards."""


def facts_note(cache: dict) -> str:
    """Numbers computed in code from the tool results so far. Given to the model so it does not misquote."""
    from .merge import merge_findings
    obs, users = {}, []
    for (name, _), res in cache.items():
        if name == "username_scan":
            users.append(res)
        else:
            obs[name] = res
    m = merge_findings(email_scan=obs.get("email_scan"), username_scans=users or None, breach=obs.get("breach_lookup"))
    s, parts = m["summary"], []
    if "email accounts" in s["checks_ok"]:
        parts.append(f"confirmed accounts: {s['confirmed']}")
        d = (obs["email_scan"].get("data") or {})
        parts.append(f"email-scan sites not checked: {d.get('errors', 0)} errored, {d.get('skipped', 0)} skipped")
    if users and "username search" in s["checks_ok"]:
        parts.append(f"possible username matches: {s['possible']}")
    if "breaches" in s["checks_ok"]:
        parts.append("breaches: " + (", ".join(m["breaches"]) or "none"))
    if s["checks_failed"]:
        parts.append("checks that did NOT run: " + ", ".join(s["checks_failed"]))
    return ("FACTS from the tools so far (computed in code, quote exactly): " + "; ".join(parts) + ".") if parts else ""


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
            facts = facts_note(cache)
            if facts:
                backend.add_user_note(facts)
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
