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
