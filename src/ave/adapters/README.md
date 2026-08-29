# `adapters/` — the language-pack seam

The stable interface a per-language adapter plugs into. The seam is now **real** — defined
in [`base.py`](base.py) as the `LanguagePack` protocol — and v1's single pack is landed.

- **The seam** (`base.LanguagePack`): a pack supplies four capabilities — finding sources
  (`find`), blast-radius extraction (`blast_radius`), fix templates (`prepare_fix`), and an
  exploit-oracle harness (`run_exploit` + `legitimate_use_holds`, inverted polarity).
- **v1's pack** (`python_authz/`): Python/FastAPI, BOLA/BFLA. Landed by the walking skeleton
  (ticket 03); ticket 04 **repointed `find()` at the real vendored target catalog**
  (`target/catalog.json`, 8 authorization instances + decoys, each bound to a by-path
  exploit oracle). The end-to-end loop drives the **anchor** instance (I-04) via a hermetic
  in-process oracle (`python_authz/_skeleton_target.py`) so `make check` runs without the
  target's environment; executing the other instances' by-path oracles in the target's
  pinned env is the next deepening (find-stage / execution).
- **The negative obligation (D3):** the stable core (`ave.graph`, `ave.state`, `ave.records`,
  `ave.policy`) must never bake in `python` / `fastapi` / `authz` naming, so a second pack
  (roadmap) can be added without reshaping the core. `get_default_pack()` is the only
  selection point today; a language/stack registry is a second-pack concern.
