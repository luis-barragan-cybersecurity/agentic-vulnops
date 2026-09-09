"""The language-pack seam — the stable interface a per-language adapter plugs into.

A "language pack" plugs a language into AVE's stable core by supplying:

  - finding sources (rule + model findings for that language/stack),
  - blast-radius extraction (caller graph / route map for that stack),
  - fix templates (what a class-level fix looks like there),
  - an exploit-oracle harness (how an exploit test is written and its polarity read).

The interface is `base.LanguagePack`. v1 ships exactly one concrete pack — `python_authz`
(Python/FastAPI, BOLA/BFLA) — landed by the walking skeleton (ticket 03), which is what
revealed the genuinely Python-specific edges. Its obligation to the vision (D3) is
**negative**: the core must never bake in `python`, `fastapi`, or `authz`, so a second
pack (roadmap) can be added without reshaping the core.
"""

from __future__ import annotations

from ave.adapters.base import FindingBatch, LanguagePack, PreparedFix


def get_default_pack() -> LanguagePack:
    """The language pack the graph runs by default. v1: the single Python/authz pack.

    Selection is deliberately trivial here — a registry keyed by language/stack is a
    second-pack concern (roadmap), not a walking-skeleton one."""
    from ave.adapters.python_authz import PythonAuthzPack

    return PythonAuthzPack()


__all__ = ["FindingBatch", "LanguagePack", "PreparedFix", "get_default_pack"]
