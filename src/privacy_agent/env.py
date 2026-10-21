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
