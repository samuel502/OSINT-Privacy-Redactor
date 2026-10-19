"""Gradio UI: shows the agent's loop live (model choice -> tool call -> observation) and the final plan."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import gradio as gr  # noqa: E402

from privacy_agent.agent import format_event, run_agent  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.schema import validate_email  # noqa: E402

JURISDICTIONS = [("EU / EEA (GDPR)", "gdpr"), ("UK (UK GDPR)", "uk_gdpr"),
                 ("California (CCPA)", "ccpa"), ("Other", "other")]


def audit(email, jurisdiction, provider, api_key):
    try:
        email = validate_email(email)
        backend = make_backend(provider, api_key=(api_key or "").strip() or None)
    except (ValueError, LLMError) as e:
        yield f"**Error:** {e}", ""
        return
    trace, final = [], ""
    for ev in run_agent(email, jurisdiction, backend):
        if ev["type"] == "final":
            final = ev["text"]
        trace.append(format_event(ev))
        yield "\n\n".join(trace), final


with gr.Blocks(title="Privacy Footprint Agent") as demo:
    gr.Markdown("# Privacy Footprint Agent\nAudit **your own** email: what is tied to it, and how to remove it. "
                "Probing runs locally; your email is never sent to the LLM, only tool results are.")
    with gr.Row():
        email = gr.Textbox(label="Your email address")
        jurisdiction = gr.Dropdown(JURISDICTIONS, value="gdpr", label="Your legal jurisdiction")
    provider = gr.Dropdown([("Groq", "groq"), ("Gemini", "gemini")], value="groq", label="LLM provider")
    api_key = gr.Textbox(label="API key (optional if GROQ_API_KEY / GEMINI_API_KEY is set)", type="password")
    run = gr.Button("Run audit", variant="primary")
    plan = gr.Markdown(label="Removal plan")
    trace = gr.Markdown(label="Agent trace")
    run.click(audit, [email, jurisdiction, provider, api_key], [trace, plan])

if __name__ == "__main__":
    demo.launch(share=bool(os.environ.get("GRADIO_SHARE")))
