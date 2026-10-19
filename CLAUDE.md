# CLAUDE.md

## Goal
Course project: a small agentic AI system in Google Colab with a Gradio interface. The model chooses among at least three distinct, real tools (at least two kinds of work, at least two supporting the core value); Python executes them and returns observations so the model can decide again. One complete user journey with data we can provide.

Project: audit your own email footprint (accounts + breaches), then plan removal (verified playbooks + GDPR/CCPA drafts).

## Layout
- `src/privacy_agent/tools/` four tools, each returns `schema.result(...)`
- `src/privacy_agent/agent.py` loop (generator of events); `llm.py` backends; `schema.py` shared helpers
- `app.py` Gradio; `cli.py` local runner (`--tools-only` skips the LLM)
- `tests/` run with `python -m pytest` (no network, no API key)

## Rules (do not break)
1. Never fabricate results. No padding lists, no default values, no guessed URLs presented as fact.
2. `unavailable` / `error` must never be shown as "nothing found".
3. The email is injected by the agent; the model must not choose it or see it.
4. Erasure requests are drafts only. No auto-sending.
5. Keep tools genuinely different in kind. Do not add near-duplicates to hit a count.
6. Playbook entries need a source and `last_verified`; unverified ones stay labelled.

## Untested / to verify first
- `llm.GroqBackend` (OpenAI-style tool calling via the `groq` SDK) is tested only with a fake client. Run one live agent loop; check the model name in console.groq.com/docs/models (default `llama-3.3-70b-versatile`) and free-tier token-per-minute limits.
- `llm.GeminiBackend` was written against the google-genai docs but NOT run against the live API. Run `python cli.py <email>` with a real key and fix any SDK mismatches (check manual function-calling and thought-signature handling for the chosen model).
- `footprint.py` holehe flags (`--only-used --no-color --no-clear -C`) and CSV column names are from memory; run `holehe --help` and one real scan, adjust parsers.
- `breaches.py` response shape (`breaches` nested list; 404 = not found) is from XposedOrNot client docs; confirm with one live call. Free API is ~1 req/s.
- Gemini free-tier quotas are small; default model alias is `gemini-flash-latest`, override with `GEMINI_MODEL`.

## Next steps
1. Verify and fill 10-15 playbook entries by hand (source + date).
2. Run the live checks above, fix, keep tests green.
3. Optional: embeddings-based retrieval; another LLM backend behind the same three-method interface (`make_backend` selects Groq or Gemini).
