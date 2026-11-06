"""Splash shown at the top of the Gradio page."""
from __future__ import annotations

__all__ = ["banner_html"]

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
