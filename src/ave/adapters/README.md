# `adapters/` — the language-pack seam

The stable interface a per-language adapter plugs into. The seam is now **real** — defined
in [`base.py`](base.py) as the `LanguagePack` protocol — and v1's single pack is landed.

- **The seam** (`base.LanguagePack`): a pack supplies four capabilities — finding sources
  (`find`), blast-radius extraction (`blast_radius`), fix templates (`prepare_fix`), and an
  exploit-oracle harness (`run_exploit` + `legitimate_use_holds`, inverted polarity).
- **v1's pack** (`python_authz/`): Python/FastAPI, BOLA/BFLA. Landed by the walking skeleton
  (ticket 03), which is what revealed the Python-specific edges. It currently drives one
  **synthetic** BOLA instance; ticket 04 repoints it at the real vendored target catalog.
- **The negative obligation (D3):** the stable core (`ave.graph`, `ave.state`, `ave.records`,
  `ave.policy`) must never bake in `python` / `fastapi` / `authz` naming, so a second pack
  (roadmap) can be added without reshaping the core. `get_default_pack()` is the only
  selection point today; a language/stack registry is a second-pack concern.
