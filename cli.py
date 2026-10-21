"""Local runner.
  python cli.py me@example.com                # full deterministic audit, no API key
  python cli.py me@example.com --agent        # agentic audit (needs GROQ_API_KEY / GEMINI_API_KEY)
  python cli.py me@example.com --out reports  # also write report.md / report.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from privacy_agent.agent import format_event, run_agent  # noqa: E402
from privacy_agent.banner import render_banner  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.pipeline import run_pipeline  # noqa: E402
from privacy_agent.schema import validate_email  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="Audit an email footprint (your own address).")
    p.add_argument("email")
    p.add_argument("--name", default=None, help="Full name, used in erasure drafts.")
    p.add_argument("--jurisdiction", default="gdpr", choices=["gdpr", "uk_gdpr", "ccpa", "other"])
    p.add_argument("--agent", action="store_true", help="Use the LLM agent instead of the pipeline.")
    p.add_argument("--tools-only", action="store_true",
                   help="Deprecated alias: the plain pipeline is now the default.")
    p.add_argument("--provider", default=None, choices=["groq", "gemini"])
    p.add_argument("--model", default=None)
    p.add_argument("--max-steps", type=int, default=14)
    p.add_argument("--out", default=None, help="Directory to write report.md / report.json.")
    p.add_argument("--no-banner", action="store_true")
    a = p.parse_args()

    if not a.no_banner:
        print(render_banner())

    email = validate_email(a.email)

    if a.agent:
        try:
            backend = make_backend(a.provider, model=a.model)
        except LLMError as e:
            sys.exit(str(e))
        for ev in run_agent(email, a.jurisdiction, backend, max_steps=a.max_steps, full_name=a.name):
            print(format_event(ev), "\n")
            if ev["type"] == "final":
                print("=" * 70, "\n", ev["text"])
        return

    bundle = None
    for ev in run_pipeline(email, a.jurisdiction, a.name):
        if ev["type"] == "step":
            print(ev["text"])
        else:
            bundle = ev["bundle"]
    print("\n" + "=" * 70 + "\n")
    print(bundle["report_md"])
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
            f.write(bundle["report_md"])
        with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
            json.dump({k: v for k, v in bundle.items() if k != "report_md"}, f, indent=2, default=str)
        print(f"\nWrote {a.out}/report.md and report.json")


if __name__ == "__main__":
    main()
