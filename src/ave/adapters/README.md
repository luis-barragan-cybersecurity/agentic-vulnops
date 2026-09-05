# `adapters/` — the language-pack seam

The stable interface a per-language adapter plugs into. The seam is now **real** — defined
in [`base.py`](base.py) as the `LanguagePack` protocol — and v1's single pack is landed.

- **The seam** (`base.LanguagePack`): a pack supplies five capabilities — finding sources
  (`find`), blast-radius extraction (`blast_radius`), a proposed remediation surface the
  policy is judged over (`fix_plan`), fix templates that realize it as a patch
  (`prepare_fix`), and an exploit-oracle harness (`run_exploit` + `legitimate_use_holds`,
  inverted polarity). `fix_plan` is the Decide-time proposal; `prepare_fix` the Prepare-time
  realization.
- **v1's pack** (`python_authz/`): Python/FastAPI, BOLA/BFLA. Landed by the walking skeleton
  (ticket 03); ticket 04 pointed it at the real vendored target (`target/catalog.json`,
  8 authorization instances + decoys, each bound to a by-path exploit oracle). `find()`
  declares one finding, the catalog's loop anchor I-04, and the other seam methods reject
  anything else. The catalog's full instance list stays ground truth for ticket 07's
  precision and recall, so no finding source may return it. The anchor runs on a hermetic
  in-process oracle (`python_authz/_skeleton_target.py`) so `make check` runs without the
  target's environment. A real finding source, and the other instances' by-path oracles in
  the target's pinned env, are the next deepening (find-stage / execution).
- **Optional capability — the pinned-env runner** (`base.PinnedEnvCapable`): a pack *may*
  also run an instance's by-path exploit oracle inside the target's own **pinned
  environment** (for `python_authz`, `target/dvrestaurant/` under Poetry / Python 3.10),
  verifying a fix against the *real* target and capturing the real attack exchange (request +
  actual deny) into `prepared_change["attack_exchange"]` for the PR body's opener. It is
  opt-in per run (`state["use_pinned_env"]`, wired from `AVE_PINNED_ENV`) and honest by
  construction: `pinned_env_available()` is False when the env is absent, and the runner
  returns a `ran=False` result rather than a fabricated pass or transcript — so `make check`,
  which has no target env, is unaffected and the hermetic oracle stays the default. The
  captured transcript passes three independent fail-closed gates (harness, runner, renderer)
  before it reaches the public PR body.
  - **Seam smell for ticket 14:** this makes the exploit-oracle harness carry **two runner
    shapes** — the hermetic in-process `run_exploit`, and this pinned-subprocess runner — and
    the seam does not yet name a Runner strategy; the core picks between them by a capability
    probe. Unifying them behind one named Runner is seam-hardening work (ticket 14). Keeping
    it an *optional* Protocol (not part of `LanguagePack`) is deliberate: a pack with no
    pinned env is not forced to implement it.
- **The negative obligation (D3):** the stable core (`ave.graph`, `ave.state`, `ave.records`,
  `ave.policy`) must never bake in `python` / `fastapi` / `authz` naming, so a second pack
  (roadmap) can be added without reshaping the core. `get_default_pack()` is the only
  selection point today; a language/stack registry is a second-pack concern.
