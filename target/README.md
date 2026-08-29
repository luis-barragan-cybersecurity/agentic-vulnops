# `target/` — the code under review

AVE's first proof runs against a **pinned fork** of the Damn Vulnerable RESTaurant API
Game, vendored here as the deliberately-vulnerable target.

**Status: vendored** (ticket 04) under [`dvrestaurant/`](dvrestaurant/), pinned at:

- **Upstream:** `github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game`
- **Commit:** `d32d09972aec7830f5f1d4a5d274cac7aae7eb82`

The snapshot is the upstream tree verbatim (its `Dockerfile`, `docker-compose.yml` and
`poetry.lock` are kept, so the pinned Python 3.10 / FastAPI 0.103 environment — the
faithful oracle runner — reproduces exactly). Upstream's committed `app/.env` (non-secret
Postgres defaults, which `docker-compose` injects anyway) is intentionally omitted, and
`__pycache__` is stripped. The seeded authorization instances and the exploit-oracle
catalog that binds them live in [`CATALOG.md`](CATALOG.md) / [`catalog.json`](catalog.json).

## Licensing (why this repo is GPL-3.0)

The upstream target is **GPL-3.0**. Vendoring it here makes the distributed repo a GPL-3.0
work (copyleft), which is why AVE ships the verbatim GPL-3.0 [`LICENSE`](../LICENSE) and
credits theowni in [`ATTRIBUTION.md`](../ATTRIBUTION.md). Per GPL-3.0 §5, every target file
AVE modifies (e.g. seeded authorization instances) must be **marked as changed and dated**.

> Upstream's `pyproject.toml` declares `license = "MIT"`, contradicting its GPL-3.0
> `LICENSE`. The `LICENSE` file governs; the MIT metadata is treated as stale and is not
> relied upon. See `ATTRIBUTION.md`.

## Test harness note

The exploit-oracle files (native `level_*.py`, AVE-seeded `ave_seed_*.py`) are **not
auto-collected** by pytest — they are invoked by path — and their **polarity is inverted**:
a passing exploit test means the target is *still vulnerable*. This is why AVE's root
`pyproject.toml` scopes pytest collection to `tests/` only, so `make check` never picks up
the vendored target's suite. Run an oracle from `dvrestaurant/`:
`docker compose run web pytest app/tests/vulns/<file>.py` (pinned env), or locally from
`dvrestaurant/app` with `DB_BACKEND=memory ENV=testing`. See [`CATALOG.md`](CATALOG.md).
