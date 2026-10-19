"""Local runner. Examples:
  python cli.py me@example.com --tools-only                    # no LLM, no API quota
  python cli.py me@example.com --jurisdiction gdpr             # full agent (needs GROQ_API_KEY or GEMINI_API_KEY)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from privacy_agent.agent import format_event, run_agent  # noqa: E402
from privacy_agent.llm import LLMError, make_backend  # noqa: E402
from privacy_agent.schema import validate_email  # noqa: E402
from privacy_agent.tools import dispatch  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="Audit an email footprint (intended for your own address) and plan removal.")
    p.add_argument("email")
    p.add_argument("--jurisdiction", default="gdpr", choices=["gdpr", "uk_gdpr", "ccpa", "other"])
    p.add_argument("--provider", default=None, choices=["groq", "gemini"])
    p.add_argument("--model", default=None)
    p.add_argument("--max-steps", type=int, default=8)
    p.add_argument("--tools-only", action="store_true", help="Run the tools directly, without an LLM.")
    a = p.parse_args()

    email = validate_email(a.email)
    ctx = {"email": email, "jurisdiction": a.jurisdiction}
    if a.tools_only:
        out = {"footprint": dispatch("footprint_probe", {}, ctx),
               "breaches": dispatch("breach_lookup", {}, ctx)}
        accounts = out["footprint"]["data"].get("confirmed_accounts", [])
        out["playbooks"] = {d: dispatch("search_playbooks", {"query": d}, ctx) for d in accounts}
        print(json.dumps(out, indent=2))
        return
    try:
        backend = make_backend(a.provider, model=a.model)
    except LLMError as e:
        sys.exit(str(e))
    for ev in run_agent(email, a.jurisdiction, backend, max_steps=a.max_steps):
        print(format_event(ev), "\n")
        if ev["type"] == "final":
            print("=" * 70, "\n", ev["text"])


if __name__ == "__main__":
    main()
