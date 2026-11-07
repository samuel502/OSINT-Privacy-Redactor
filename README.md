# Privacy Footprint Agent

An agentic AI tool that shows what the internet can find about **your own** email address or username, then helps you plan its removal. It looks up accounts and breaches with free open-source tools, an AI model decides what to check next, and findings link to removal routes (opt-out pages and ready-to-send GDPR/CCPA drafts). It runs in Google Colab with a Gradio interface and your own free Groq API key.

## Status (read this first)
| Part | State |
|---|---|
| Email account lookup (`email_scan`, user-scanner) | Built. Checked live on one real email: 17 accounts found, confirmed by its owner. One example, not a benchmark. |
| Username lookup (`username_scan`, user-scanner) | Built, tested offline only. Not yet tested live on a normal connection. |
| Breach lookup (`breach_lookup`, XposedOrNot) | Built. |
| Removal playbooks (`search_playbooks`) | 8 hand-checked entries. A researched list of about 540 opt-out routes exists but is not loaded yet. |
| Erasure drafts (`draft_erasure_request`) | Built. Drafts only. |
| Maigret username search | Planned, pending a live test. |
| Single Colab notebook | Built (quickstart). Sample-data mode planned. |

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
- **The model never sees or chooses the email.** The agent injects it into tool calls. Before tool results reach the model, the email (also URL-encoded) and the full name are replaced with placeholders, including inside erasure drafts and error messages. You still see the real drafts.
- **Your email does go to the lookup services.** That is how a lookup works: user-scanner's sites, XposedOrNot, Gravatar and GitHub receive it.
- **Untrusted text is filtered and marked.** Profile fields, breach names and holehe hints from third-party sites are whitelisted and length-capped. Bios and free text are dropped, because they could contain instructions aimed at the model. Every tool result goes to the model inside `<untrusted-data id=…>` markers with a random per-run id, which the data cannot close. Profile details of username matches (possibly a stranger's page) are not sent to the model at all.
- **Nothing unsafe renders.** Scan values are HTML-escaped in the cards. The model's answer is shown with raw HTML and images disabled, links only over https, and terminal output has control characters removed.
- **Colab only, no public link.** The page runs inside the notebook with `share=False`; there is no share link, login, local launcher or CLI. The Groq key comes only from Colab Secrets and is never saved.
- **Password-reset-triggering sites are skipped by default**, because checking them can send the target a notification email.
- **Intended for your own address.** The app has no ownership check, because nobody can prove ownership of an address by ticking a box. The UI and this README state the intended use instead: addresses and usernames you own or have permission to check. Looking up other people is out of scope for this project.
- **No fabricated results.** Nothing is padded, defaulted or guessed. Unverified playbook entries are labelled.
- **Human in the loop.** Erasure requests are drafts. The tool never reads your mailbox, and you click any confirmation links yourself. It does not solve CAPTCHAs.

## Run it (Google Colab only)
1. Open [`notebooks/colab_quickstart.ipynb`](notebooks/colab_quickstart.ipynb) in Google Colab.
2. Get a free Groq key at console.groq.com/keys. In Colab, open **Secrets** (key icon, left sidebar), add a secret named `GROQ_API_KEY` with your key, and turn on notebook access.
3. Run the cells in order. The page opens inside the notebook. Re-running the launch cell restarts it.

The scan works without a key; only the agentic audit needs it. Your key is read from Colab Secrets when the app starts and kept in memory only: it is never written to a file, printed, or put in an environment variable. Never paste it into a cell, chat or screenshot.

Some sites block cloud IP addresses, so results are a floor, not a complete list.

### Development
`python -m pytest` runs the tests locally (no network, no key, no Colab needed).

## Add playbooks
Edit `src/privacy_agent/data/playbooks.json`. For each service, visit its opt-out or deletion page yourself, then record `opt_out_url`, `steps_summary`, whether email confirmation is needed, `verified: true` and `last_verified`. Unverified entries stay labelled.

## Limitations
- Lookups depend on third-party sites. Some block cloud IPs or rate-limit; results are a floor, not a complete list.
- Absence on a site is not proof the email is unused there.
- Username matches are leads, not proof.
- Free API tiers are rate-limited.
- Smaller open models can emit malformed tool calls; the Groq backend retries these.
- Opt-out links go stale, which is why entries carry `last_verified`.
- Not legal advice.

## Credits
user-scanner (MIT), XposedOrNot, holehe (GPL-3.0, run as a separate process).
