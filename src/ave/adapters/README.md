# `adapters/` — the language-pack seam

This directory reserves the seam a future language pack plugs into. **Nothing is designed
here yet** — by design (D3).

- v1's single adapter (Python/FastAPI, BOLA/BFLA) lands during the walking skeleton
  (ticket 03), which is what will reveal the genuine Python-specific edges.
- The stable core (`ave.graph`, `ave.state`, `ave.records`, `ave.policy`) must never bake
  in `python` / `fastapi` / `authz` naming, so a second pack (roadmap) can be added without
  reshaping the core.

A language pack supplies: finding sources, an exploit-oracle harness, blast-radius
extraction, and fix templates. See `ave/adapters/__init__.py`.
