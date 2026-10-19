# Constraints & Testing

## Constraints
1. Free by default: holehe, XposedOrNot free API, free Gemini key. No paid services required.
2. Graceful degradation: if a tool is missing, rate-limited, or blocked, it returns `unavailable`/`error`, and the agent reports it under "Could not check" instead of guessing. If no verified playbook exists, the agent falls back to an erasure-request draft.
3. Human in the loop: nothing is sent automatically.
4. Intended for your own address: stated in the UI and README, not enforced by a gate.

## Automated tests (`python -m pytest`, no network or API key)
- Email validation, including flag-lookalike inputs such as `--help@x.com`.
- holehe CSV/text parsing; footprint never pads results; `unavailable` when no source can run.
- Breach parsing, 404 handled as "not found, not proof", network failure as `unavailable`.
- Playbook exact/alias/unknown lookups; unverified entries are flagged.
- Erasure drafts cite the correct law per jurisdiction; invalid domains rejected.
- Agent loop with a scripted backend: tools run and observations are fed back; email pinned and hidden from the model; repeated calls cached; step limit enforced; backend failure becomes an error event.

## Manual checks (need network / keys; record results here)
- [ ] `python cli.py <own email> --tools-only` returns plausible, non-padded output within ~2.5 minutes.
- [ ] Full agent run with a real Gemini key completes and cites only observed data.
- [ ] Gradio shows the trace live and the final plan.
