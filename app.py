"""Gradio UI, Colab only. Launched from notebooks/colab_quickstart.ipynb via launch().

The Groq key comes from Colab Secrets and is passed in as an argument. It is held in this
process's memory only: never written to a file and never put in os.environ (so the lookup
subprocesses do not inherit it).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import gradio as gr  # noqa: E402

from privacy_agent.banner import banner_html  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.scan import ui_agent, ui_scan  # noqa: E402

JURISDICTIONS = [("EU / EEA (GDPR)", "gdpr"), ("UK (UK GDPR)", "uk_gdpr"),
                 ("California (CCPA)", "ccpa"), ("Other", "other")]
BLANK = ("", "", "", None)  # after the trace: report, checklist, drafts, files
NO_KEY = ("No Groq key found. Add a Colab Secret named `GROQ_API_KEY` (key icon, left sidebar), "
          "turn on notebook access, and run the launch cell again.")

# Gradio keeps its own copy of every download file (reports hold an email and raw results).
# Every 30 min, delete copies older than 1 h; Gradio also clears this cache when the server restarts.
DELETE_CACHE = (1800, 3600)

# Gradio 6 takes the theme in launch(), not Blocks().
THEME = gr.themes.Soft()


def mask_key(key: str | None) -> str:
    """Show only the start and last 4 characters. Short keys are fully hidden."""
    key = (key or "").strip()
    if len(key) < 12:
        return "••••••••"
    return f"{key[:4]}••••••••{key[-4:]}"


def key_line(key: str | None) -> str:
    """One plain line for the page. Never contains the full key."""
    if (key or "").strip():
        return f"🔑 **Groq key in use** (from Colab Secrets): `{mask_key(key)}`"
    return f"⚠️ {NO_KEY}"


def show_fields(mode):
    return gr.update(visible=mode in ("email", "both")), gr.update(visible=mode in ("username", "both"))


def build_demo(groq_key: str | None = None) -> gr.Blocks:
    """The page. groq_key lives only in this closure."""
    groq_key = (groq_key or "").strip() or None

    def audit_agent(email, full_name, jurisdiction):
        if not groq_key:
            yield (f"**Error:** {NO_KEY}",) + BLANK
            return
        try:
            backend = make_backend("groq", api_key=groq_key)
        except (ValueError, LLMError) as e:
            yield (f"**Error:** {e}",) + BLANK
            return
        yield from ui_agent(email, jurisdiction, backend, full_name=(full_name or "").strip() or None)

    with gr.Blocks(title="OSINT Privacy Redactor", delete_cache=DELETE_CACHE) as demo:
        gr.HTML(banner_html())
        gr.Markdown("Check **your own** email or username: which accounts and breaches show up, "
                    "and how to opt out of OSINT lookup sites. Lookups run from this Colab session and "
                    "send your email or username to the services being checked (user-scanner's sites, "
                    "XposedOrNot, Gravatar, GitHub). In the agentic audit your email and name are removed "
                    "from everything sent to the LLM.")
        mode = gr.Radio([("Email", "email"), ("Username", "username"), ("Both", "both")],
                        value="email", label="What to check")
        with gr.Row():
            email = gr.Textbox(label="Your email address", scale=3)
            username = gr.Textbox(label="Your username", scale=3, visible=False)
            full_name = gr.Textbox(label="Full name (optional, agentic mode only)", scale=2)
            jurisdiction = gr.Dropdown(JURISDICTIONS, value="gdpr", label="Jurisdiction (agentic mode)")
        pivot = gr.Checkbox(label="Also search the usernames the sites report for my email "
                                  "(finds profile links; slower)", value=True)
        gr.Markdown("_Use this on addresses and usernames you own or have permission to check._")
        run_plain = gr.Button("Scan (no LLM key needed)", variant="primary")
        with gr.Accordion("Agentic audit (needs your free Groq key in Colab Secrets)", open=False):
            gr.Markdown(key_line(groq_key))
            run_agent_btn = gr.Button("Run agentic audit", interactive=bool(groq_key))
        with gr.Tabs():
            with gr.Tab("Exposure report"):
                report = gr.HTML()
            with gr.Tab("Agent summary"):
                drafts = gr.Markdown()
            with gr.Tab("Opt-out checklist"):
                checklist = gr.HTML()
            with gr.Tab("Agent trace"):
                trace = gr.Markdown()
            with gr.Tab("Download"):
                files = gr.Files(label="report.md / report.json")
        outs = [trace, report, checklist, drafts, files]
        mode.change(show_fields, mode, [email, username])
        run_plain.click(ui_scan, [mode, email, username, pivot], outs)
        run_agent_btn.click(audit_agent, [email, full_name, jurisdiction], outs)
    return demo


def in_colab() -> bool:
    return "google.colab" in sys.modules


def launch(groq_key: str | None = None, debug: bool = True):
    """Start the page inside the Colab notebook. Never a public share link."""
    if not in_colab():
        raise RuntimeError("This tool runs only in Google Colab. Open notebooks/colab_quickstart.ipynb there.")
    # share=False explicitly: in Colab, Gradio would otherwise create a public link by default.
    return build_demo(groq_key).launch(share=False, debug=debug, theme=THEME)
