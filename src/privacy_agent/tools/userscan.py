"""Tools: email_scan and username_scan (live lookups, powered by user-scanner, MIT).

user-scanner runs as a subprocess and writes JSON; we parse that JSON. Reasons:
  * a crash or hang in one of its ~2,800 site modules cannot take the app down;
  * its console output carries banners and promotional text, which never reach the model;
  * the tool keeps working if the package changes its internals, as long as the JSON stays.

What reaches the model is deliberately small. Profile fields come from third-party sites,
so they are untrusted text: only a short whitelist is kept, each value is capped, and
free-text fields such as bios are dropped (a bio could contain instructions aimed at the model).

Honesty rules carried into the output:
  * "Registered"/"Found" is a hit. "Not Registered"/"Not Found" is absence on that site only.
  * "Error" and "Skipped" are counted and reported, never turned into "not found".
  * Sites that may email the target a password-reset notice are skipped unless include_loud=True.
  * A username hit is only a "possible_match": the same handle can belong to someone else.
  * A scan that hits its time limit is "timed out", with the sites answered so far counted.

Process control: stdin is closed (user-scanner otherwise waits forever on an "update? (y/n)"
prompt when PyPI has a newer version), and the scanner runs in its own process group so a
timeout or cancel kills it and every process it started.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

from ..schema import result, validate_email

SOURCE = "user-scanner"
TIMEOUT_S = int(os.environ.get("USER_SCANNER_TIMEOUT", "120"))
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

HIT = {"registered", "found", "taken"}
ABSENT = {"not registered", "not found", "available"}
# Fields safe to show the model. Anything else (bio, about, description...) is dropped.
KEEP_EXTRA = ("name", "username", "joined", "created", "followers", "following", "location",
              "last_profile_update", "last_active", "last_seen", "has_public_page")
MAX_VALUE = 80
MAX_HITS = 60


def validate_username(username: str) -> str:
    username = (username or "").strip().lstrip("@")
    if not USERNAME_RE.match(username):  # also blocks leading '-' (CLI flag lookalikes)
        raise ValueError(f"Invalid username: {username!r}")
    return username


def _clean_extra(extra: dict | None) -> dict:
    out = {}
    for k, v in (extra or {}).items():
        if str(k).lower() in KEEP_EXTRA and isinstance(v, (str, int, float)):
            out[str(k).lower()] = str(v)[:MAX_VALUE]
    return out


def _avatar(media) -> str:
    """Profile picture link if the site gave one. https only, capped. Never fetched by us."""
    url = (media or {}).get("avatar") if isinstance(media, dict) else None
    if not (isinstance(url, str) and url.startswith("https://")) or "default" in url.lower():
        return ""  # sites return a grey placeholder when there is no real picture: not a profile picture
    return url[:300]


def parse_rows(rows: list[dict], kind: str) -> dict:
    """Turn user-scanner JSON rows into the compact summary the agent sees."""
    hits, counts = [], {"checked": 0, "absent": 0, "errors": 0, "skipped": 0}
    not_checked = {"error_sites": [], "skipped_sites": []}
    for r in rows:
        status = str(r.get("status", "")).strip().lower()
        site = str(r.get("site_name", ""))[:40]
        if status == "skipped":
            counts["skipped"] += 1
            if site and len(not_checked["skipped_sites"]) < 120:
                not_checked["skipped_sites"].append(site)
        elif status == "error":
            counts["errors"] += 1
            if site and len(not_checked["error_sites"]) < 120:
                not_checked["error_sites"].append(site)
        elif status in HIT:
            counts["checked"] += 1
            hit = {"site": str(r.get("site_name", ""))[:60],
                   "category": str(r.get("category", ""))[:30],
                   "url": str(r.get("url", ""))[:120]}
            details = _clean_extra(r.get("extra"))
            if details:
                hit["details"] = details
            avatar = _avatar(r.get("media"))
            if avatar:
                hit["avatar"] = avatar
            hits.append(hit)
        elif status in ABSENT:
            counts["checked"] += 1
            counts["absent"] += 1
    label = "registered" if kind == "email" else "possible_match"
    for h in hits:
        h["label"] = label
        h["source"] = SOURCE
    return {"hits": hits[:MAX_HITS], "hit_count": len(hits), **counts, **not_checked}


def _why(returncode, tail: list, value: str) -> str:
    """Last line of the scanner's own output, with the scanned value removed, capped."""
    lines = [ln.strip() for ln in tail if ln.strip()]
    if not lines:
        return f" (exit code {returncode}, no error text)"
    return " (" + lines[-1].replace(value, "<value>")[:200] + ")"


# One console line per site with --all, indented: "  [✔] Site (user): Registered".
# user-scanner's own banner and update messages start at column 0, so they are not counted.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^\s+\[(✔|✘|!|~)\]\s")
_KIND = {"✔": "found", "✘": "absent", "!": "errors", "~": "skipped"}


def new_progress() -> dict:
    return {"found": 0, "absent": 0, "errors": 0, "skipped": 0}


def count_line(line: str, progress: dict) -> None:
    m = _LINE.match(_ANSI.sub("", line))
    if m:
        progress[_KIND[m.group(1)]] += 1


class ScanTimeout(Exception):
    """The scan hit its time limit. Carries the per-site counts seen before it was stopped."""

    def __init__(self, seconds: int, progress: dict, cancelled: bool = False):
        super().__init__(f"timed out after {seconds}s")
        self.seconds, self.progress, self.cancelled = seconds, dict(progress), cancelled


def kill_tree(proc) -> None:
    """Kill the scanner and every process it started (its whole process group)."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)  # start_new_session=True made pid the group id
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # /T: child processes too
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run_capped(cmd: list, timeout: float, env: dict | None = None, progress: dict | None = None,
               cancel: threading.Event | None = None) -> tuple[int, list]:
    """Run cmd with stdin closed, counting per-site lines into `progress` as they arrive.

    Returns (returncode, last output lines). On timeout or cancel the whole process group is
    killed and ScanTimeout is raised, so nothing keeps running in the background.
    """
    progress = new_progress() if progress is None else progress
    tail: list = []
    group = ({"start_new_session": True} if os.name == "posix"
             else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP})
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", env=env, **group)

    def read():
        for line in proc.stdout:
            count_line(line, progress)
            tail.append(line)
            del tail[:-20]

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    start = time.monotonic()
    try:
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                kill_tree(proc)
                raise ScanTimeout(int(time.monotonic() - start), progress, cancelled=True)
            if time.monotonic() - start >= timeout:
                kill_tree(proc)
                raise ScanTimeout(int(timeout), progress)
            time.sleep(0.25)
    finally:
        kill_tree(proc)  # no-op when it already exited; kills it on any other exception
        reader.join(timeout=5)
    return proc.returncode, tail


def _run(flag: str, value: str, include_loud: bool, timeout: float | None = None,
         progress: dict | None = None, cancel: threading.Event | None = None) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.json")
        cmd = [sys.executable, "-m", "user_scanner", flag, value, "--all", "-f", "json", "-o", out]
        if include_loud:
            cmd.append("--allow-loud")
        # Windows consoles default to cp1252 and crash on the emoji user-scanner prints when piped.
        # Unbuffered, so each site's line arrives as it finishes (live progress).
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        code, tail = run_capped(cmd, TIMEOUT_S if timeout is None else min(timeout, TIMEOUT_S),
                                env=env, progress=progress, cancel=cancel)
        if not os.path.exists(out):
            raise RuntimeError("user-scanner produced no JSON output" + _why(code, tail, value))
        with open(out, encoding="utf-8") as fh:
            rows = json.load(fh)
    if not isinstance(rows, list):
        raise RuntimeError("unexpected user-scanner output shape")
    return rows


def _installed() -> bool:
    import importlib.util
    return importlib.util.find_spec("user_scanner") is not None


def timeout_result(t: ScanTimeout) -> dict:
    """A timed-out scan: counted, never 'nothing found'. Hits seen before the stop are not listed,
    because the scan did not finish and its JSON was never written."""
    p = t.progress
    answered = p["found"] + p["absent"]
    head = "Stopped (scan cancelled)" if t.cancelled else f"Timed out after {t.seconds}s"
    data = {"timed_out": True, "seconds": t.seconds, "checked": answered, "found": p["found"],
            "errors": p["errors"], "skipped": p["skipped"]}
    return result("error", data, SOURCE,
                  error=f"{head}: {answered} sites answered ({p['found']} found), {p['skipped']} skipped, "
                        f"{p['errors']} errored; every other site was NOT checked.")


def _scan(flag: str, value: str, kind: str, include_loud: bool, timeout: float | None = None,
          progress: dict | None = None, cancel: threading.Event | None = None) -> dict:
    try:
        if not _installed():
            return result("unavailable", source=SOURCE,
                          error="user-scanner is not installed (pip install user-scanner).")
        rows = _run(flag, value, include_loud, timeout=timeout, progress=progress, cancel=cancel)
    except ScanTimeout as t:
        return timeout_result(t)
    except Exception as e:  # noqa: BLE001
        return result("error", source=SOURCE, error=f"{type(e).__name__}: {e}")
    data = parse_rows(rows, kind)
    if data["checked"] == 0:
        return result("error", data, SOURCE,
                      error="No site gave a usable answer (blocked, offline or rate limited).")
    notes = []
    if data["errors"]:
        notes.append(f"{data['errors']} sites errored or were blocked and are NOT counted as 'not found'.")
    if data["skipped"]:
        notes.append(f"{data['skipped']} sites skipped because checking them can trigger a "
                     "password-reset email to the target.")
    if kind == "username":
        notes.append("Username matches are possible matches only: the handle may belong to someone else.")
    else:
        notes.append("Absence on a site is not proof the email is unused there.")
    return result("ok", data, SOURCE, note=" ".join(notes))


def email_scan(email: str, include_loud: bool = False, timeout: float | None = None,
               progress: dict | None = None, cancel: threading.Event | None = None) -> dict:
    return _scan("-e", validate_email(email), "email", include_loud, timeout, progress, cancel)


def username_scan(username: str, timeout: float | None = None, progress: dict | None = None,
                  cancel: threading.Event | None = None) -> dict:
    return _scan("-u", validate_username(username), "username", False, timeout, progress, cancel)
