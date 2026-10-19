# Privacy Footprint Agent

An agentic AI tool that audits **your own** email address: it finds which services have an account tied to it and which known breaches include it, then builds a prioritised plan to remove that exposure (opt-out steps plus ready-to-send GDPR/CCPA erasure drafts). It runs locally or in Google Colab with a Gradio interface and a free Groq or Gemini API key.

## Why an agent
The right next step depends on what the earlier tools found. A breached account with a known deletion route should come first; a service with no playbook needs a legal template instead; a probe that fails should be reported, not guessed. The model chooses the tools and the order, Python runs them, and the observations go back to the model until it can write the plan. The Gradio UI shows every step of that loop.

## Tools (four, three kinds of work)
| Tool | Kind | What it does |
|---|---|---|
| `footprint_probe` | discovery | holehe + Gravatar: services with an account registered to the email. Confirmed hits only. |
| `breach_lookup` | discovery (different source) | Free XposedOrNot API: known breaches containing the email. |
| `search_playbooks` | retrieval | Exact-match then TF-IDF search over `data/playbooks.json` (opt-out URL, steps, verified flag, date). |
| `draft_erasure_request` | action | GDPR / UK GDPR / CCPA erasure email draft. Draft only; nothing is sent. |

Every tool returns the same shape (`status: ok | unavailable | error`). `unavailable` means "could not check", never "nothing found".

## Design decisions
- **The model never sees or chooses the email.** The agent injects it into tool calls, so the model cannot be steered into probing another address, and the address is not sent to the LLM. Tool results are.
- **Intended for your own address.** There is no ownership gate (anyone could just type a confirmation), so the UI and README state the intended use instead.
- **No fabricated results.** Nothing is padded, defaulted, or guessed. Unverified playbook entries are labelled.
- **Human in the loop.** Erasure requests are drafts. You send them.

## Run locally
```bash
pip install -r requirements.txt
read -rsp "Groq API key: " GROQ_API_KEY; echo; export GROQ_API_KEY   # key stays hidden while you type (console.groq.com/keys)
# or: export GEMINI_API_KEY=...      # Google AI Studio key

python -m pytest                                              # tests, no network or key needed
python cli.py me@example.com --tools-only                    # tools only, no LLM quota used
python cli.py me@example.com                                 # full agent loop (--provider groq|gemini)
python app.py                                                 # Gradio UI
```

## Run in Colab
Open `notebooks/colab_quickstart.ipynb`, add `GROQ_API_KEY` (and/or `GEMINI_API_KEY`) to Colab Secrets, and run the cells.

## Add playbooks (this is the part that makes it useful)
Edit `src/privacy_agent/data/playbooks.json`. For each service, visit its opt-out or deletion page yourself, then record `opt_out_url`, `steps_summary`, whether email confirmation is needed, `verified: true`, and `last_verified`. The shipped entries are unverified seeds. Add `lookup_service` entries for the email-lookup sites you want people to opt out of.

## Limitations
- holehe depends on third-party sites and breaks or rate-limits often; results are a floor, not a complete list.
- Free tiers are rate-limited. Groq's allows more requests per minute but has a small tokens-per-minute cap (observations are truncated for that reason); Gemini's free tier has small daily limits. Set `GROQ_MODEL` / `GEMINI_MODEL` if a default model is unavailable.
- Smaller open models can emit malformed tool calls; the Groq backend retries these.
- Opt-out links can go stale. That is why entries carry `last_verified`.
- Not legal advice.
