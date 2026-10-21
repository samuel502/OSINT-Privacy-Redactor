"""Colored splash. Degrades truecolor -> 256-color -> plain. Safe on non-TTY (Colab/CI logs)."""
from __future__ import annotations
import os
import sys

__all__ = ["render_banner", "banner_html"]

_STOPS = ((0, 255, 209), (0, 176, 255), (124, 92, 255), (255, 92, 205))

_ART = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
██████╗ ██████╗ ██╗██╗   ██╗ █████╗  ██████╗██╗   ██╗
██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝
██████╔╝██████╔╝██║██║   ██║███████║██║      ╚████╔╝
██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║       ╚██╔╝
██║     ██║  ██║██║ ╚████╔╝ ██║  ██║╚██████╗   ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝   ╚═╝
██████╗ ███████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║███████║██║        ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║        ██║   ██║   ██║██╔══██╗
██║  ██║███████╗██████╔╝██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

_TAGLINE = "privacy footprint discovery · gdpr / ccpa opt-out automation · local-first"


def _mode() -> str:
    if os.environ.get("NO_COLOR"):
        return "plain"
    if os.environ.get("FORCE_COLOR") or sys.stdout.isatty():
        return "truecolor" if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"} else "256"
    return "plain"


def _lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def _color_at(t: float):
    t = min(max(t, 0.0), 1.0)
    n = len(_STOPS) - 1
    i = min(int(t * n), n - 1)
    return _lerp(_STOPS[i], _STOPS[i + 1], t * n - i)


def _to_256(rgb):
    r, g, b = (min(255, max(0, c)) for c in rgb)
    return 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)


def _paint(line: str, width: int, mode: str) -> str:
    if mode == "plain":
        return line
    out = []
    for i, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        rgb = _color_at(i / max(width - 1, 1))
        out.append(f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{ch}" if mode == "truecolor"
                   else f"\x1b[38;5;{_to_256(rgb)}m{ch}")
    return "".join(out) + "\x1b[0m"


def render_banner() -> str:
    """ANSI banner for terminals: git bash/mintty, Windows Terminal, Colab, CI logs."""
    if os.name == "nt":
        os.system("")  # lets cmd.exe honour ANSI once VT processing is enabled
    lines = _ART.strip("\n").splitlines()
    width = max(len(l) for l in lines)
    mode = _mode()
    body = "\n".join(_paint(l.ljust(width).rstrip(), width, mode) for l in lines)
    return f"\n{body}\n  {_paint(_TAGLINE, width, mode)}\n"


def banner_html() -> str:
    """Same art for Gradio: <pre> with a CSS gradient clipped to the glyphs."""
    art = "\n".join(l.rstrip() for l in _ART.strip("\n").splitlines())
    return (
        '<div style="background:#0b0f14;padding:18px 22px;border-radius:12px;border:1px solid #1b2430;">'
        '<pre style="margin:0;font:700 11.5px/1.06 ui-monospace,Menlo,Consolas,monospace;'
        'background:linear-gradient(90deg,#00ffd1,#00b0ff,#7c5cff,#ff5ccd);'
        '-webkit-background-clip:text;background-clip:text;color:transparent;">'
        f'{art}</pre>'
        f'<div style="margin-top:12px;font:600 11px ui-monospace,monospace;letter-spacing:.4px;'
        'background:linear-gradient(90deg,#00ffd1,#00b0ff,#7c5cff,#ff5ccd);'
        f'-webkit-background-clip:text;background-clip:text;color:transparent;">{_TAGLINE}</div></div>'
    )
