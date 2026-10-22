# CLAUDE.md

## Goal
Course project (ITC 754): a small agentic AI system in Google Colab with a Gradio interface. The model chooses among at least three distinct, real tools (at least two kinds of work, at least two supporting the core value); Python executes them and returns observations so the model can decide again. One complete user journey with data we can provide. The course brief (GUIDELINE.md) wins over any other doc.

Project: show what is findable about your own email or username (accounts, breaches), then plan removal (playbooks plus GDPR/CCPA drafts). Also a local tool and portfolio piece.

## Layout
- `src/privacy_agent/tools/` tools, each returns `schema.result(...)`: `userscan.py` (email_scan, username_scan), `breaches.py`, `playbooks.py`, `erasure.py`, `footprint.py` (holehe fallback)
- `src/privacy_agent/agent.py` loop (generator of events); `llm.py` backends; `schema.py` shared helpers
- `app.py` Gradio; `cli.py` local runner (`--tools-only` skips the LLM)
- `tests/` run with `python -m pytest` (no network, no API key); `tests/fixtures/` holds SYNTHETIC sample data only

## Rules (do not break)
1. Never fabricate results. No padding lists, no default values, no guessed URLs presented as fact.
2. `unavailable` / `error` must never be shown as "nothing found". Errors and skipped sites are counted in the output.
3. The email is injected by the agent; the model must not choose it or see it.
4. Erasure requests are drafts only. No auto-sending. No mailbox access. No CAPTCHA solving.
5. Keep tools genuinely different in kind. Do not add near-duplicates to hit a count (footprint_probe is a fallback, not a declared tool).
6. Playbook and registry entries need a source and `last_verified`; unverified ones stay labelled.
7. Text from third-party sites is untrusted: whitelist and cap fields before it reaches the model.
8. Username hits are "possible matches". Never call them confirmed.
9. Real personal data stays out of fixtures and the repo. Samples are synthetic and labelled.

## Untested / to verify first
- `llm.GroqBackend`: run one live agent loop and confirm the forced final answer on the last step works.
- `llm.GeminiBackend` was written against the docs but NOT run against the live API.
- `username_scan` is tested offline only. Run it live from a normal (non-cloud) connection.
- Maigret is not integrated. Decide after a live test whether it adds real accounts beyond user-scanner.
- `breaches.py` response shape confirmed once live; free API is about 1 req/s.
- One pre-existing failing test: `test_footprint_second_pass_recovers_unresolved_sites` (also fails on the untouched code). Diagnose.

## Next steps
1. Merge layer: one de-duplicated report across tools with confirmed / possible / unverified labels.
2. Load the researched opt-out registry (about 40 routes for the demo) and add `start_optout` (dry-run by default).
3. Real two-tool agent trace saved as JSON; Gradio modes (Email / Username / Both).
4. Single Colab notebook with the 7 required headings, sample-data mode, then writeup, checkpoints and demo.
