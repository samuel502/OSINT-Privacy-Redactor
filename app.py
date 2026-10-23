"""Gradio UI. Works with no API key (deterministic audit) or with one (agentic audit)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import gradio as gr  # noqa: E402

from privacy_agent.agent import format_event, run_agent  # noqa: E402
from privacy_agent.banner import banner_html  # noqa: E402
from privacy_agent.env import key_status, load_env  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.scan import ui_scan  # noqa: E402
from privacy_agent.schema import validate_email  # noqa: E402

load_env()

JURISDICTIONS = [("EU / EEA (GDPR)", "gdpr"), ("UK (UK GDPR)", "uk_gdpr"),
                 ("California (CCPA)", "ccpa"), ("Other", "other")]
BLANK = ("", "", "", None)  # after the trace: report, checklist, drafts, files
KEY_HELP = """1. Get a free key at console.groq.com/keys. It is shown **once**, so copy it.
2. Open a terminal in the project folder and run this one line. Typing is hidden, and the key never
   appears on screen or in your command history:

   `read -s -p "Paste key (hidden): " K; printf 'GROQ_API_KEY=%s\\n' "$K" > .env; unset K; echo`
3. Run `git status`. `.env` must **not** be listed (it is git-ignored). Never use `git add -f .env`.
4. Restart the app (Ctrl+C, then `python app.py`). This page then shows the key as masked, e.g. `gsk_••••••••abcd`.
5. No file? Paste the key into the masked box below instead. It is used for this session only and never saved.
Never paste your key into chat, a command line or a screenshot."""


def _plain_html(text: str) -> str:
    import html
    return f'<div style="white-space:pre-wrap">{html.escape(text)}</div>'


def show_fields(mode):
    return gr.update(visible=mode in ("email", "both")), gr.update(visible=mode in ("username", "both"))


def audit_agent(email, full_name, jurisdiction, provider, api_key):
    try:
        email = validate_email(email)
        backend = make_backend(provider, api_key=(api_key or "").strip() or None)
    except (ValueError, LLMError) as e:
        yield (f"**Error:** {e}",) + BLANK
        return
    trace, last = [], None
    for ev in run_agent(email, jurisdiction, backend, max_steps=14,
                        full_name=(full_name or "").strip() or None):
        trace.append(format_event(ev))
        yield ("\n\n".join(trace),) + BLANK
        last = ev
    if last and last["type"] == "final":
        yield ("\n\n".join(trace), _plain_html(last["text"]), "", "", None)


with gr.Blocks(title="OSINT Privacy Redactor", theme=gr.themes.Soft()) as demo:
    gr.HTML(banner_html())
    gr.Markdown("Check **your own** email or username: which accounts and breaches show up, "
                "and how to opt out of OSINT lookup sites. Lookups run from this machine; "
                "your email is never sent to an LLM.")
    mode = gr.Radio([("Email", "email"), ("Username", "username"), ("Both", "both")],
                    value="email", label="What to check")
    with gr.Row():
        email = gr.Textbox(label="Your email address", scale=3)
        username = gr.Textbox(label="Your username", scale=3, visible=False)
        full_name = gr.Textbox(label="Full name (optional, agentic mode only)", scale=2)
        jurisdiction = gr.Dropdown(JURISDICTIONS, value="gdpr", label="Jurisdiction (agentic mode)")
    own = gr.Checkbox(label="This is my own email address / username", value=False)
    pivot = gr.Checkbox(label="Also search the usernames the sites report for my email (finds profile links; slower)",
                        value=True)
    run_plain = gr.Button("Scan (no LLM key needed)", variant="primary")
    with gr.Accordion("Agentic audit (needs a free Groq or Gemini key)", open=False):
        key_line = gr.Markdown(key_status("groq"))
        with gr.Accordion("How to save your key safely", open=False):
            gr.Markdown(KEY_HELP)
        with gr.Row():
            provider = gr.Dropdown([("Groq", "groq"), ("Gemini", "gemini")], value="groq",
                                   label="Provider")
            api_key = gr.Textbox(label="Optional: paste a key here instead (used for this session only, never saved)",
                                 type="password")
        run_agent_btn = gr.Button("Run agentic audit")
    with gr.Tabs():
        with gr.Tab("Exposure report"):
            report = gr.HTML()
        with gr.Tab("Opt-out checklist"):
            checklist = gr.Markdown()
        with gr.Tab("Erasure drafts"):
            drafts = gr.Markdown()
        with gr.Tab("Agent trace"):
            trace = gr.Markdown()
        with gr.Tab("Download"):
            files = gr.Files(label="report.md / report.json")
    outs = [trace, report, checklist, drafts, files]
    provider.change(key_status, [provider, api_key], key_line)
    api_key.change(key_status, [provider, api_key], key_line)
    mode.change(show_fields, mode, [email, username])
    run_plain.click(ui_scan, [mode, email, username, own, pivot], outs)
    run_agent_btn.click(audit_agent, [email, full_name, jurisdiction, provider, api_key], outs)

if __name__ == "__main__":
    demo.launch(share=os.environ.get("GRADIO_SHARE", "").lower() in {"1", "true", "yes"})
