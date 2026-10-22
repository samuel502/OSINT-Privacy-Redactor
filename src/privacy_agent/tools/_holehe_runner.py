"""Standalone holehe driver. Run as a subprocess; never imported by the app.

holehe's own CLI builds its httpx client with follow_redirects left at the default (False),
so any site that has since moved to https, to www, or to a new host answers 3xx with an empty
body, the module's parser crashes, and holehe reports the crash as "[x] rate limit". On this
machine that was 118 of 121 sites. Following redirects drops it to 64.

Two side benefits of doing it here rather than importing holehe:
  - holehe is GPLv3, so a process boundary keeps the app's own code clean for relicensing.
  - we get typed records instead of console text, so no regex parsing.

Usage:
    python _holehe_runner.py me@example.com

JSON on stdout, a one-line summary on stderr.
"""
from __future__ import annotations

import json
import os
import sys

HTTP_TIMEOUT = float(os.environ.get("HOLEHE_HTTP_TIMEOUT", "20"))


async def _run(email: str, out: list) -> None:
    import httpx
    import trio
    from holehe.core import get_functions, import_submodules, launch_module

    async def one(module):
        try:
            await launch_module(module, email, client, out)
        except Exception as e:  # holehe's own handler can KeyError; never lose the site
            out.append({"name": getattr(module, "__name__", "?"), "domain": "",
                        "exists": False, "rateLimit": False,
                        "error": f"{type(e).__name__}: {e}"})

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        async with trio.open_nursery() as nursery:
            for module in get_functions(import_submodules("holehe.modules")):
                nursery.start_soon(one, module)


def collect(email: str) -> list:
    import trio
    out: list = []
    trio.run(_run, email, out)
    return out


def main(argv) -> int:
    if len(argv) < 2:
        print(json.dumps({"ok": False, "error": "usage: _holehe_runner.py EMAIL"}))
        return 2
    try:
        records = collect(argv[1])
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return 1
    failed = [r for r in records if r.get("rateLimit") or r.get("error")]
    found = [r for r in records if r.get("exists")]
    print(f"{len(records)} sites · {len(found)} accounts · {len(failed)} unresolved",
          file=sys.stderr)
    print(json.dumps({"ok": True, "records": records}, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
