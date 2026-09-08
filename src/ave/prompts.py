"""Prompts-as-code — load a versioned prompt by its manifest id.

Every phase that reasons registers its prompt in ``prompts/manifest.json`` so the text is
versioned, diffable, and eval-addressable rather than buried inline in a call site (Phase
0's compounding export, internal-first for v1). This loader is the core's neutral (D3) way
to read one: it resolves an id to its file through the manifest and returns the text. No
templating engine — a prompt is plain text a caller may ``.format(...)``; keeping the
substitution at the call site keeps the manifest a registry, not a language.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

# src/ave/prompts.py -> repo root is two parents up.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _REPO_ROOT / "prompts" / "manifest.json"


class PromptNotFound(KeyError):
    """No prompt with that id is registered in the manifest — a missing registration, not a
    prompt to guess at."""


@lru_cache(maxsize=1)
def _manifest() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return data


def prompt_version(prompt_id: str) -> int:
    """The registered version of a prompt — carried into the run record so a run names the
    prompt version it reasoned under."""
    entry = _manifest().get("prompts", {}).get(prompt_id)
    if entry is None:
        raise PromptNotFound(prompt_id)
    return int(entry["version"])


def load_prompt(prompt_id: str) -> str:
    """The text of the registered prompt `prompt_id`, read from the file the manifest points
    at (relative to ``prompts/``)."""
    entry = _manifest().get("prompts", {}).get(prompt_id)
    if entry is None:
        raise PromptNotFound(prompt_id)
    path = _REPO_ROOT / "prompts" / str(entry["file"])
    return path.read_text(encoding="utf-8")
