# Privacy Footprint Agent

An agentic AI tool that shows what the internet can find about **your own** email address or username, then helps you plan its removal. It looks up accounts and breaches with free open-source tools, an AI model decides what to check next, and findings link to removal routes (opt-out pages and ready-to-send GDPR/CCPA drafts). It runs locally or in Google Colab with a Gradio interface and a free Groq or Gemini API key.

## Status (read this first)
| Part | State |
|---|---|
| Email account lookup (`email_scan`, user-scanner) | Built. Checked live on one real email: 17 accounts found, confirmed by its owner. One example, not a benchmark. |
| Username lookup (`username_scan`, user-scanner) | Built, tested offline only. Not yet tested live on a normal connection. |
| Breach lookup (`breach_lookup`, XposedOrNot) | Built. |
| Removal playbooks (`search_playbooks`) | 8 hand-checked entries. A researched list of about 540 opt-out routes exists but is not loaded yet. |
| Erasure drafts (`draft_erasure_request`) | Built. Drafts only. |
| Maigret username search | Planned, pending a live test. |
| Automated opt-out (`start_optout`) | Planned. Dry-run first; the user always confirms. |
| Single Colab notebook, sample-data mode | Planned. |

## Why an agent
The right next step depends on what earlier tools found. A handle revealed by an account can become a username search; a breached account with a known deletion route should come first; a service with no playbook needs a legal template; a check that fails must be reported, not guessed. The model chooses the tools and the order, Python runs them, and observations go back to the model until it can write the plan. The Gradio UI shows each step.

## Tools
| Tool | Kind | What it does |
|---|---|---|
| `email_scan` | live lookup | [user-scanner](https://github.com/kaifcodec/user-scanner) (MIT): which of ~240 services have an account registered to the email. |
| `username_scan` | live lookup | user-scanner username search. Hits are **possible matches** only; a handle can belong to someone else. |
| `breach_lookup` | live lookup | Free XposedOrNot API: known breaches containing the email. |
| `search_playbooks` | stored retrieval | Search `data/playbooks.json` (opt-out URL, steps, verified flag, date). |
| `draft_erasure_request` | action | GDPR / UK GDPR / CCPA erasure email draft. Nothing is sent. |

`footprint_probe` (holehe + Gravatar) remains as a fallback and for the no-AI pipeline. holehe's last release was in 2022, so it is no longer the main source.

Every tool returns one shape (`status: ok | unavailable | error`). `unavailable` means "could not check", never "nothing found". Errors and skipped sites are counted and reported.

## Design decisions
- **The model never sees or chooses the email.** The agent injects it into tool calls. Tool results reach the model, not the address.
- **Untrusted text is filtered.** Profile fields from third-party sites are whitelisted and length-capped before they reach the model. Bios and free text are dropped, because they could contain instructions aimed at the model.
- **Password-reset-triggering sites are skipped by default**, because checking them can send the target a notification email.
- **Intended for your own address.** There is no ownership gate (anyone could type a confirmation), so the UI and this README state the intended use. Looking up other people is out of scope.
- **No fabricated results.** Nothing is padded, defaulted or guessed. Unverified playbook entries are labelled.
- **Human in the loop.** Erasure requests are drafts. The tool never reads your mailbox, and you click any confirmation links yourself. It does not solve CAPTCHAs.

## Run locally
Steps for Git Bash on Windows. On Mac or Linux, activate with `source .venv/bin/activate`.
```bash
git clone https://github.com/samuel502/OSINT-Privacy-Redactor.git && cd OSINT-Privacy-Redactor
python -m venv .venv                  # private folder for this project's packages
source .venv/Scripts/activate         # you should now see (.venv)
pip install -r requirements.txt
python app.py                         # open http://127.0.0.1:7860
```
The scan needs no key. Only the optional agentic audit needs a free Groq key (console.groq.com/keys).

### Saving your key safely (optional, for the agentic audit)
The key is shown once, so copy it, then run this one line. Typing is hidden and the key never appears in
your command history or on screen:
```bash
read -s -p "Paste key (hidden): " K; printf 'GROQ_API_KEY=%s\n' "$K" > .env; unset K; echo
```
1. `.env` is in `.gitignore`, so it is never committed. Check with `git status`: `.env` must not be listed.
2. Never use `git add -f .env`, and never paste the key into chat, a command or a screenshot.
3. Restart the app. The page shows a masked line such as `gsk_••••••••abcd` when a key is in use.
4. Prefer not to use a file? Paste the key into the masked box on the page (this session only, not saved).

```bash
python -m pytest                                              # tests, no network or key needed
python cli.py me@example.com --tools-only                    # tools only, no LLM quota used
python cli.py me@example.com                                 # full agent loop (--provider groq|gemini)
```
A VPN can make lookups fail or return blocked results. Turn it off for a fair scan.

## Run in Colab
Open `notebooks/colab_quickstart.ipynb`, add `GROQ_API_KEY` (and/or `GEMINI_API_KEY`) to Colab Secrets, and run the cells. Some sites block cloud IP addresses, so a local run can find more.

## Add playbooks
Edit `src/privacy_agent/data/playbooks.json`. For each service, visit its opt-out or deletion page yourself, then record `opt_out_url`, `steps_summary`, whether email confirmation is needed, `verified: true` and `last_verified`. Unverified entries stay labelled.

## Limitations
- Lookups depend on third-party sites. Some block cloud IPs or rate-limit; results are a floor, not a complete list.
- Absence on a site is not proof the email is unused there.
- Username matches are leads, not proof.
- Free API tiers are rate-limited. Set `GROQ_MODEL` / `GEMINI_MODEL` if a default model is unavailable.
- Smaller open models can emit malformed tool calls; the Groq backend retries these.
- Opt-out links go stale, which is why entries carry `last_verified`.
- Not legal advice.

## Credits
user-scanner (MIT), XposedOrNot, holehe (GPL-3.0, run as a separate process).
