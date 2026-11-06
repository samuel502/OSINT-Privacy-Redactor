"""Shared helpers: email validation and one uniform result shape for every tool."""
from __future__ import annotations

import re
from datetime import datetime, timezone

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def validate_email(email: str) -> str:
    """Return a cleaned email or raise ValueError. Also blocks CLI-flag lookalikes."""
    email = (email or "").strip()
    if len(email) > 254 or email.startswith("-") or not EMAIL_RE.match(email):
        raise ValueError(f"Invalid email address: {email!r}")
    return email


# ---------------------------------------------------------------- output safety
# Model text and third-party text are rendered as Markdown (Gradio) or printed to a terminal.

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def md_safe(text) -> str:
    """Model-written Markdown, made inert: no raw HTML and no images (an image URL is fetched
    by the browser, so it could carry data out). Ordinary links and formatting stay."""
    s = str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"!(?=\s*\[)", r"\\!", s)


def md_escape(text) -> str:
    """Third-party text shown as literal Markdown text: no formatting, links, HTML or tables."""
    return _MD_SPECIAL.sub(r"\\\1", str(text or "").replace("\n", " "))


def md_fence(body: str, lang: str = "") -> str:
    """Code block whose fence is longer than any backtick run inside, so the body cannot close it."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{body}\n{fence}"


def strip_ctrl(text) -> str:
    """Remove terminal control characters (ANSI escapes and similar); keeps newlines and tabs."""
    return _CTRL.sub("", str(text or ""))


def result(status: str, data: dict | None = None, source: str = "",
           error: str | None = None, note: str | None = None) -> dict:
    """Uniform tool output.

    status: "ok"          -> the check ran and `data` is trustworthy
            "unavailable" -> the check could not run (tool/key/network missing)
            "error"       -> the check ran but failed
    An empty `data` with status "ok" means "checked, nothing found".
    "unavailable" must never be read as "nothing found".
    """
    if status not in {"ok", "unavailable", "error"}:
        raise ValueError(f"bad status {status!r}")
    return {
        "status": status,
        "data": data or {},
        "source": source,
        "error": error,
        "note": note,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
