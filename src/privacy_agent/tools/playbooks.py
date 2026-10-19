"""Tool 3 (retrieval): find the opt-out / deletion playbook for a service.

Retrieval = exact domain/alias match first, then TF-IDF cosine similarity over a small
hand-curated JSON file. This is keyword vector search, not neural semantic search; swap in
embeddings later if wanted (see CLAUDE.md). Every entry carries `verified` / `last_verified`.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from ..schema import result

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "playbooks.json"


_STOP = {"the", "a", "an", "of", "to", "and", "for", "in", "on", "your", "my", "site", "s", "account"}


def _tok(s: str):
    return re.findall(r"[a-z0-9]+", s.lower())


def _norm_domain(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    return s.split("/")[0]


class PlaybookIndex:
    def __init__(self, entries):
        self.entries = entries
        docs = [Counter(_tok(self._text(e))) for e in entries]
        n = len(docs)
        df = Counter(t for d in docs for t in d)
        self.idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
        self.vecs = [self._vec(d) for d in docs]

    @staticmethod
    def _text(e):
        return " ".join([e["domain"], e["name"], " ".join(e.get("aliases", [])),
                         e.get("category", ""), e.get("steps_summary", "")])

    def _vec(self, counts):
        v = {t: c * self.idf.get(t, 0.0) for t, c in counts.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def search(self, query: str, k: int = 3, category: str | None = None):
        dom = _norm_domain(query)
        looks_like_domain = " " not in query.strip() and "." in dom
        root = ".".join(dom.split(".")[-2:]) if looks_like_domain else dom
        exact = [e for e in self.entries
                 if dom in (e["domain"], *e.get("aliases", [])) or root in (e["domain"], *e.get("aliases", []))]
        scored = [(1.0, e) for e in exact]
        if not looks_like_domain:  # free-text query: fuzzy match; domain-like queries only match exactly
            q = self._vec(Counter(t for t in _tok(query) if t not in _STOP))
            for vec, e in zip(self.vecs, self.entries):
                s_ = sum(w * vec.get(t, 0.0) for t, w in q.items())
                if s_ > 0.15:
                    scored.append((s_, e))
        if category:
            scored = [(s_, e) for s_, e in scored if e.get("category") == category]
        scored.sort(key=lambda x: -x[0])
        return scored[:k]


def load_entries(path: Path = DATA_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def search_playbooks(query: str, category: str | None = None) -> dict:
    query = (query or "").strip()
    if not query:
        return result("error", source="local playbooks", error="Empty query.")
    try:
        index = PlaybookIndex(load_entries())
    except Exception as e:  # noqa: BLE001
        return result("unavailable", source="local playbooks", error=f"Could not load playbooks: {e}")
    hits = index.search(query, category=category)
    matches = [{**{k: e.get(k) for k in (
        "domain", "name", "category", "opt_out_url", "steps_summary",
        "requires_email_confirmation", "needs_captcha", "verified", "last_verified", "notes")},
        "score": round(s, 3)} for s, e in hits]
    note = None if matches else "No playbook on file for this query; use draft_erasure_request as the fallback."
    if any(not m["verified"] for m in matches):
        note = (note or "") + " Entries with verified=false have NOT been manually checked; tell the user to confirm the steps."
    return result("ok", {"matches": matches}, "local playbooks", note=note.strip() if note else None)
