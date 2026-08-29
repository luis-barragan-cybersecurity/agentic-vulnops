# `target/` — the code under review

AVE's first proof runs against a **pinned fork** of the Damn Vulnerable RESTaurant API
Game, vendored here as the deliberately-vulnerable target.

**Status: not yet vendored.** This directory reserves the location. The fork is brought in
during **ticket 04** (seeded-instance catalog + oracles), pinned at:

- **Upstream:** `github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game`
- **Commit:** `d32d09972aec7830f5f1d4a5d274cac7aae7eb82`

## Licensing (why this repo is GPL-3.0)

The upstream target is **GPL-3.0**. Vendoring it here makes the distributed repo a GPL-3.0
work (copyleft), which is why AVE ships the verbatim GPL-3.0 [`LICENSE`](../LICENSE) and
credits theowni in [`ATTRIBUTION.md`](../ATTRIBUTION.md). Per GPL-3.0 §5, every target file
AVE modifies (e.g. seeded authorization instances) must be **marked as changed and dated**.

> Upstream's `pyproject.toml` declares `license = "MIT"`, contradicting its GPL-3.0
> `LICENSE`. The `LICENSE` file governs; the MIT metadata is treated as stale and is not
> relied upon. See `ATTRIBUTION.md`.

## Test harness note (for later tickets)

The exploit-oracle files (`level_*.py`) are **not auto-collected** by pytest — they are
invoked by path — and their **polarity is inverted**: a passing exploit test means the
target is *still vulnerable*. This is why `pyproject.toml` scopes pytest collection to
`tests/` only.
