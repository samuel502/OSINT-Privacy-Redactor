"""Minimal .env loader. No dependency, and it never echoes a value.

`export GROQ_API_KEY=gsk_...` puts the key on the command line, so it lands in
~/.bash_history. With a gitignored .env the key is typed once, into a file, and never
appears in a shell command.
"""
from __future__ import annotations

import os
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


def load_env(path: Path | None = None) -> int:
    """Set os.environ from KEY=VALUE lines. The real environment wins. Returns how many were set."""
    p = path or ENV_PATH
    if not p.exists():
        return 0
    n = 0
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v and not os.environ.get(k):
            os.environ[k] = v
            n += 1
    return n


MIN_SHARE_PASSWORD = 12


def share_settings(environ=None) -> dict:
    """Gradio launch settings. A public share link needs a login, or we refuse to start.

    Anyone with the link could otherwise run scans from this machine's IP and spend the
    API key in .env. Credentials come from GRADIO_USERNAME / GRADIO_PASSWORD (.env or environment).
    Raises SystemExit with a plain message (never echoing the password).
    """
    environ = os.environ if environ is None else environ
    if environ.get("GRADIO_SHARE", "").lower() not in {"1", "true", "yes"}:
        return {"share": False}
    user = (environ.get("GRADIO_USERNAME") or "").strip()
    pw = environ.get("GRADIO_PASSWORD") or ""
    if not user or len(pw) < MIN_SHARE_PASSWORD:
        raise SystemExit("GRADIO_SHARE is set but no login is configured. A share link is public, so set "
                         f"GRADIO_USERNAME and GRADIO_PASSWORD (at least {MIN_SHARE_PASSWORD} characters) "
                         "in .env, or unset GRADIO_SHARE.")
    return {"share": True, "auth": (user, pw)}


KEY_VARS = {"groq": ("GROQ_API_KEY",), "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY")}


def mask_key(key: str) -> str:
    """Show only the start and last 4 characters. Short keys are fully hidden."""
    key = (key or "").strip()
    if len(key) < 12:
        return "••••••••"
    return f"{key[:4]}••••••••{key[-4:]}"


def key_status(provider: str, typed: str | None = None, environ=None) -> str:
    """One plain line for the UI: is a key in use, from where, masked. Never returns the full key."""
    environ = os.environ if environ is None else environ
    name = "Groq" if provider == "groq" else "Gemini"
    typed = (typed or "").strip()
    if typed:
        return f"🔑 **{name} key in use** (typed in this page, this session only): `{mask_key(typed)}`"
    for var in KEY_VARS.get(provider, ()):
        if environ.get(var):
            return f"🔑 **{name} key in use** (from `.env` / environment, `{var}`): `{mask_key(environ[var])}`"
    return f"⚠️ **No {name} key found.** Add it to `.env` and restart, or paste it below."
