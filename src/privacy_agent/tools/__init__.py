"""Tool registry: LLM-facing declarations + a dispatcher.

Security design: the user's email and jurisdiction are injected from the agent context.
The model cannot choose or change the email, so it cannot be steered into probing
a different address. Tool outputs (not the email) are what reach the LLM.
"""
from __future__ import annotations

from ..schema import result
from .breaches import breach_lookup
from .erasure import draft_erasure_request
from .footprint import footprint_probe
from .playbooks import search_playbooks
from .publicprofiles import public_profiles
from .userscan import email_scan, username_scan

CATEGORIES = ["account_service", "lookup_service", "aggregator", "browser_config"]

DECLARATIONS = [
    {"name": "email_scan",
     "description": "Check which online services have an account registered to the user's email "
                    "(user-scanner, ~240 sites). Takes no arguments. Lists confirmed accounts with "
                    "a few profile details; reports how many sites errored or were skipped. "
                    "Absence is not proof. May take a few minutes."},
    {"name": "username_scan",
     "description": "Search public profile pages for a USERNAME (user-scanner, thousands of sites). "
                    "Use it on a handle found in email_scan details, or one the user provides. "
                    "Hits are POSSIBLE matches only: the same handle can belong to someone else.",
     "parameters": {"type": "object",
                    "properties": {"username": {"type": "string",
                                                "description": "A handle without the @, e.g. 'jdoe42'"}},
                    "required": ["username"]}},
    {"name": "breach_lookup",
     "description": "Check which known data breaches include the user's email (XposedOrNot). "
                    "Takes no arguments."},
    {"name": "search_playbooks",
     "description": "Look up the opt-out / deletion playbook for services. STRONGLY prefer ONE "
                    "batched call with `queries` = the list of every confirmed account domain, "
                    "instead of one call per domain. Use `query` only for a single domain or a "
                    "free-text search. Entries may be marked unverified.",
     "parameters": {"type": "object",
                    "properties": {
                        "query": {"type": "string",
                                  "description": "A single domain or service name"},
                        "queries": {"type": "array", "items": {"type": "string"},
                                    "description": "Batch: many domains at once (preferred)"},
                        "category": {"type": "string", "enum": CATEGORIES,
                                     "description": "Optional filter. 'lookup_service' = the "
                                                    "email-OSINT sites that profile you from your "
                                                    "address; 'aggregator' = data brokers; "
                                                    "'browser_config' = device fingerprinting."}},
                    "required": []}},
    {"name": "draft_erasure_request",
     "description": "Draft (never send) a GDPR/CCPA erasure request email for one service. "
                    "Use when a service has no verified playbook or when email erasure is the right route.",
     "parameters": {"type": "object",
                    "properties": {"platform_domain": {"type": "string",
                                                       "description": "Domain of the service, e.g. 'reddit.com'"}},
                    "required": ["platform_domain"]}},
]


def dispatch(name: str, args: dict, ctx: dict) -> dict:
    """Run one tool. Never raises: failures come back as an error result."""
    args = args or {}
    try:
        if name == "email_scan":
            r = email_scan(ctx["email"])
            if r["status"] == "unavailable":  # user-scanner missing: fall back to holehe + Gravatar
                fb = footprint_probe(ctx["email"])
                fb["note"] = "Fallback: user-scanner unavailable, used holehe + Gravatar. " + (fb.get("note") or "")
                return fb
            return r
        if name == "username_scan":
            return username_scan(str(args.get("username", "")))
        if name == "footprint_probe":  # kept for the no-LLM pipeline; not declared to the model
            return footprint_probe(ctx["email"])
        if name == "public_profiles":  # used by the no-LLM scan; not declared to the model
            return public_profiles(ctx["email"])
        if name == "breach_lookup":
            return breach_lookup(ctx["email"])
        if name == "search_playbooks":
            return search_playbooks(args.get("query"), args.get("category"), args.get("queries"))
        if name == "draft_erasure_request":
            return draft_erasure_request(ctx["email"], str(args.get("platform_domain", "")),
                                         ctx.get("jurisdiction", "other"), ctx.get("full_name"))
    except Exception as e:  # noqa: BLE001
        return result("error", source=name, error=f"{type(e).__name__}: {e}")
    return result("error", source=name, error=f"Unknown tool: {name}")
