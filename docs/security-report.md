# Security report

Required by `docs/security-framework.md` section 5. It records what was tested, with which tools, what was found, what was fixed and what risk remains.

**Review date:** 2026-11-05
**Scope:** `src/privacy_agent/`, `app.py`, `cli.py`, `notebooks/colab_quickstart.ipynb`
**Method:** manual code review against `CLAUDE.md` rules 1-9 and the framework's risk table (section 1), then fixes in small steps. The full test suite ran after each step.

## 1. What was tested, and with which tools

| Check | Tool | Run? | Result |
|---|---|---|---|
| Unit and behaviour tests | pytest | Yes, after every fix | 136 passed, 0 failed, 0 warnings (115 before the review) |
| Attack tests (framework section 4) | pytest, `tests/test_security.py` | Yes | 21 tests, all passing |
| Code scanning | Bandit, Semgrep | **No** | Not installed |
| Dependency audit | pip-audit | **No** | Installed, not run |
| Secret scanning | gitleaks | **No** | Not installed |
| AI red teaming | Promptfoo, garak | **No** | Not installed |
| Live agent run | Groq / Gemini | **No** | Not run since these changes (see section 4) |

All tests run offline with synthetic data (`test.user@example.com`). They need no network and no API key.

### Attack test coverage (framework section 4)

| Hostile input in the framework | Covered by |
|---|---|
| Fake profile bio telling the AI to ignore its instructions | `test_fingerprint_card_bio_is_dropped_and_fields_whitelisted`, `test_holehe_hints_drop_free_form_others`, `test_tool_results_are_marked_and_cannot_be_closed_from_inside`; existing `test_userscan.py`, `test_publicprofiles.py` |
| Breach description containing instructions | `test_breach_name_with_instructions_or_html_is_dropped` |
| Username or bio containing HTML or `<script>` | `test_breach_name_with_instructions_or_html_is_dropped`, `test_trace_fence_cannot_be_closed_by_tool_data`, `test_model_answer_cannot_render_html_or_images`, `test_agent_summary_escapes_breach_names_and_fences_drafts` |
| Scan result trying to make a tool fetch an outside URL | `test_cards_drop_plain_http_links`; avatar links never reach the model (`test_tool_results_are_marked_and_cannot_be_closed_from_inside`). No tool takes a URL argument |
| User input that is a prompt, not an email or username | Existing validation tests (`test_tools.py`, `test_scan.py`) |
| Request to show the system prompt | `test_system_prompt_holds_no_secrets` checks that there is nothing secret to leak. No live extraction attempt |
| Very long or malformed input | `test_breach_list_is_capped`, `test_breach_200_with_unknown_shape_is_an_error_not_clean`, `test_playbook_queries_are_bounded` |
| A scan that would make the agent loop | Existing step-limit, cache and per-turn limit tests in `test_agent.py`; `test_forced_answer_keeps_the_invented_link_warning` |

The framework asks for a folder of hostile inputs. The inputs are written inline in the tests for now.

## 2. What was found and fixed

Ranked by severity. Line numbers are as of this review.

| # | Finding | Framework risk | Fix | Where |
|---|---|---|---|---|
| R1 | **The model saw the user's email and name.** Erasure drafts put `Account email: …` and the full name into the tool result, which went to the LLM unchanged. Error messages could also contain the address. This broke CLAUDE.md rule 3. The old test only checked the prompts. | Sensitive data leak | Every tool result is redacted before it reaches the model: the email (also URL-encoded) and the full name are replaced with `<your email>` / `<your name>`. The UI still shows the real drafts. | `agent.py:26-46`, `agent.py:213-216` |
| R5 | **Hallucination warnings were dropped** whenever a run hit its step limit (`note =` instead of `note +=`). Invented links went unflagged in exactly the runs most likely to contain them. | Rule 1 (no fabrication) | One-character fix. | `scan.py:590` |
| R2 | **Third-party text reached the model uncapped:** breach names (any length, any characters, any count), holehe's free-form `others` hints, and fingerprint.to bios and fields. Tool output was not marked as untrusted. | Indirect prompt injection | Breach names: limited to 100 names of 60 plain characters each. fingerprint.to cards: bio dropped, fields whitelisted and capped. holehe hints: capped, `others` dropped. Playbook queries bounded. Every result now goes to the model inside `<untrusted-data id=…>` markers with a random per-run id that the data cannot close. A system-prompt rule says text inside the markers is data only. Avatar links and the profile details of username matches are no longer sent to the model. | `breaches.py:20-22, 47-58`; `fingerprint_to.py:92-104`; `footprint.py:79-83`; `playbooks.py:27-28, 129-136`; `agent.py:49-76, 114-116`; `llm.py:181-183` |
| R3 | **Untrusted text could render.** The model's Markdown answer was shown unfiltered, so an image could carry data out. Tool data could close the trace's code fence. Breach names were inserted into Markdown as-is. Plain `http://` links were allowed. Terminal escape codes were printed as-is. | Unsafe output (XSS) | New helpers: `md_safe` (no raw HTML or images in model text), `md_escape` (third-party text shown literally), `md_fence` (a fence the content cannot close), `strip_ctrl` (terminal control characters removed). Applied to the trace, the agent summary, the saved reports and all CLI output. Cards accept https links only. | `schema.py:18-46`; `agent.py:227-242`; `scan.py:131-133, 163, 212, 543, 548, 592`; `report.py:228, 305`; `cli.py:33, 85-95` |
| R4 | **Failures could look like "nothing found":** fingerprint.to returned `ok` with zero cards when a bot check blocked it; a 200 response from the breach API without a `breaches` key meant "0 breaches"; holehe's errored sites were left out of the report's counts. | Rule 2 | Zero cards now returns `unavailable`. An unexpected breach-API response returns `error`. Errored sites are counted as not checked in the Markdown and terminal reports. | `fingerprint_to.py:165-174`; `breaches.py:47-49`; `report.py:199-204, 285-290` |
| R6 | **A public Gradio link had no login.** With `GRADIO_SHARE`, anyone with the link could run scans from the user's IP and spend the API key in `.env`. In Colab, Gradio makes a public link by default. | Excessive exposure | `share_settings()` refuses to start a public link unless `GRADIO_USERNAME` and a `GRADIO_PASSWORD` of 12+ characters are set. It never prints the password. `app.py` and the Colab notebook both launch through it. Colab reads the login from Secrets. | `env.py:33-53`; `app.py:100`; notebook cells 0, 2, 5; `.env.example:9-12` |
| R7 | **Report files piled up.** Each run left a temp folder holding the email and raw results, and Gradio kept its own copies. | Sensitive data leak | The previous run's folder is deleted before a new one is written (still `mkdtemp`: private, unpredictable name). `gr.Blocks(delete_cache=(1800, 3600))` removes Gradio's copies older than 1 hour. | `scan.py:445-455`; `app.py:48, 53` |
| R9 | **The UI text was wrong:** it said "your email is never sent to an LLM" (false before R1), and nothing said that `--deep` submits the email to fingerprint.to, which is itself an OSINT site. | Transparency | UI text, `--deep` help and README design decisions now match what the code does. | `app.py:49-52`; `cli.py:54`; `README.md:34-38` |

**Already handled when the review started, so no change:** a fixed tool allowlist (`agent.py:13`); per-turn, username-scan, draft and step limits; usernames may only come from `email_scan`; drafts only, never sent; password-reset-triggering sites skipped by default; subprocesses called with argument lists (no shell) and leading `-` rejected; HTML escaping in the result cards; `.env` and `reports/` gitignored; keys masked in the UI.

**Also fixed during the review:** a Gradio 6 deprecation warning. `theme` moved from `gr.Blocks()` to `launch()` (`app.py:51, 100`, notebook cell 5).

## 3. Remaining risk

### Not done yet (framework requirements)
- **No CI.** There is no `.github/workflows`, so Bandit, Semgrep, pip-audit, gitleaks and pytest do not run on push (framework section 3).
- **Dependencies are not pinned.** `requirements.txt` uses ranges (`gradio>=4.44`, `holehe>=1.15`, …). The framework asks for pins and a dependency audit.
- **No red teaming.** Promptfoo and garak have not been run, and there is no live system-prompt extraction test.
- **The attack inputs are written inline** in `tests/test_security.py` rather than kept in a folder.

### Still possible after the fixes
- **Prompt injection is reduced, not eliminated.** Whitelisted fields (for example `name` or `location`, up to 80 characters) from sites where the email is registered still reach the model, inside the markers. A model can still follow injected text. What limits the damage: the report's facts and counts come from code (`merge.py`, `facts_note`), the tool list and limits are enforced in code, links are checked against tool output, and nothing is sent automatically.
- **Usernames come from third-party sites.** `username_scan` accepts handles that `email_scan` reported, so a hostile site could plant a handle. This is limited to 2 scans per run and a strict username format.
- **Redaction matches exact text only.** Masked or reformatted forms of the email (such as holehe's `t****@e****.com`) and names shorter than 3 characters are not replaced.
- **The full email appears in local output.** The CLI and the Markdown report put it in the header (`report.py:189`, `report.py:275`). This is local and `reports/` is gitignored, but the framework says not to log full emails by default.
- **Leftover files.** Gradio's cached copies survive until the next cleanup cycle or server restart. The last run's temp folder stays until the next run or until the OS cleans its temp directory.
- **The browser contacts third-party sites.** Profile pictures load straight from each site, so those sites see the user's IP. The UI says so.
- **Lookup services receive the email.** That is how a lookup works. `--deep` also sends it to fingerprint.to. This is disclosed in the UI, the CLI help and the README.
- **The draft check is loose.** Any substring match of 3+ characters between a domain and a breach name allows a draft (`agent.py:98`). This is low risk because the output is a draft the user sends themselves.

### Not verified live
- **The Groq and Gemini backends have not been run with the new marked string results.** Groq now gets the string as tool content. Gemini gets `{"result": "<string>"}` as its function response, which is written against the docs and untested (`GeminiBackend` was never run live; see CLAUDE.md).
- **The Colab notebook has not been run in Colab.** Only its JSON and its launch call are checked by tests.

## 4. Next checks, in order
1. Run one live agent loop on Groq with a test email and confirm the model still reads the marked results and cites only observed data.
2. Run `pip-audit -r requirements.txt` and record the result here.
3. Add CI (pytest, pip-audit, gitleaks, Bandit) and pin dependencies.
4. Move the attack inputs into a fixtures folder and add a Promptfoo run before release.
