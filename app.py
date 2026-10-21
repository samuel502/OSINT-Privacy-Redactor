"""Gradio UI. Works with no API key (deterministic audit) or with one (agentic audit)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import gradio as gr  # noqa: E402

from privacy_agent.agent import format_event, run_agent  # noqa: E402
from privacy_agent.banner import banner_html  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.pipeline import run_pipeline  # noqa: E402
from privacy_agent.report import render_checklist, render_drafts  # noqa: E402
from privacy_agent.schema import validate_email  # noqa: E402

JURISDICTIONS = [("EU / EEA (GDPR)", "gdpr"), ("UK (UK GDPR)", "uk_gdpr"),
                 ("California (CCPA)", "ccpa"), ("Other", "other")]
BLANK = ("", "", "", "", None)


def _write(bundle):
    d = tempfile.mkdtemp(prefix="redactor-")
    md, js = os.path.join(d, "privacy-report.md"), os.path.join(d, "privacy-report.json")
    with open(md, "w", encoding="utf-8") as f:
        f.write(bundle["report_md"])
    with open(js, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in bundle.items() if k != "report_md"}, f, indent=2, default=str)
    return [md, js]


def _render(bundle):
    return (bundle["report_md"], render_checklist(bundle["checklist"]),
            render_drafts(bundle["drafts"]), _write(bundle))


def audit_no_llm(email, full_name, jurisdiction):
    try:
        email = validate_email(email)
    except ValueError as e:
        yield (f"**Error:** {e}",) + BLANK
        return
    trace = []
    for ev in run_pipeline(email, jurisdiction, (full_name or "").strip() or None):
        if ev["type"] == "step":
            trace.append("- " + ev["text"])
            yield ("\n".join(trace),) + BLANK
        else:
            yield ("\n".join(trace),) + _render(ev["bundle"])


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
        yield ("\n\n".join(trace), last["text"], "", "", None)


with gr.Blocks(title="OSINT Privacy Redactor", theme=gr.themes.Soft()) as demo:
    gr.HTML(banner_html())
    gr.Markdown("Audit **your own** email: what is tied to it, and how to remove it. "
                "Probing runs locally; the address is never sent to the LLM, only tool results are.")
    with gr.Row():
        email = gr.Textbox(label="Your email address", scale=3)
        full_name = gr.Textbox(label="Full name (optional, for erasure drafts)", scale=2)
        jurisdiction = gr.Dropdown(JURISDICTIONS, value="gdpr", label="Your legal jurisdiction")
    run_plain = gr.Button("Audit (no LLM key needed)", variant="primary")
    with gr.Accordion("Agentic audit (needs a free Groq or Gemini key)", open=False):
        with gr.Row():
            provider = gr.Dropdown([("Groq", "groq"), ("Gemini", "gemini")], value="groq",
                                   label="Provider")
            api_key = gr.Textbox(label="API key (or set GROQ_API_KEY / GEMINI_API_KEY)",
                                 type="password")
        run_agent_btn = gr.Button("Run agentic audit")
    with gr.Tabs():
        with gr.Tab("Report"):
            report = gr.Markdown()
        with gr.Tab("Checklist"):
            checklist = gr.Markdown()
        with gr.Tab("Erasure drafts"):
            drafts = gr.Markdown()
        with gr.Tab("Agent trace"):
            trace = gr.Markdown()
        with gr.Tab("Download"):
            files = gr.Files(label="report.md / report.json")
    outs = [trace, report, checklist, drafts, files]
    run_plain.click(audit_no_llm, [email, full_name, jurisdiction], outs)
    run_agent_btn.click(audit_agent, [email, full_name, jurisdiction, provider, api_key], outs)

if __name__ == "__main__":
    demo.launch(share=os.environ.get("GRADIO_SHARE", "").lower() in {"1", "true", "yes"})
