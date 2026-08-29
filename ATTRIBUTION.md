# Attribution & upstream provenance

## AVE

AVE — Autonomous Vulnerability Eradication — is licensed under **GPL-3.0-or-later**
(see [`LICENSE`](./LICENSE)).

## Target under review: Damn Vulnerable RESTaurant

AVE's first proof runs against a **pinned fork** of the Damn Vulnerable RESTaurant
API Game, used here as the deliberately-vulnerable target codebase.

- **Upstream:** `github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game`
- **Author:** theowni
- **Pinned commit:** `d32d09972aec7830f5f1d4a5d274cac7aae7eb82`
- **Upstream license:** **GPL-3.0** (the `LICENSE` file is the controlling grant).

> **Upstream metadata note:** upstream's `pyproject.toml` declares `license = "MIT"`,
> which contradicts its GPL-3.0 `LICENSE` file. The full GPL-3.0 `LICENSE` text is the
> controlling distribution grant; the `pyproject` field is treated as stale and is **not**
> relied upon as an MIT grant. This inconsistency is flagged, not resolved, and should be
> normalized in the fork.

### GPL-3.0 obligations honored (fork vendored under `target/dvrestaurant/`, ticket 04)

The target fork is vendored under [`target/dvrestaurant/`](./target/dvrestaurant/). The
following obligations apply and are why this repo carries the GPL-3.0 `LICENSE`:

- **Copyleft** — a distributed modified fork is itself GPL-3.0; the verbatim GPL-3.0
  `LICENSE` is retained.
- **Notices & attribution** — upstream copyright/author notices are preserved; theowni /
  the upstream repo is credited here and in the README.
- **State changes (GPL-3.0 §5)** — every file AVE modified is marked as changed and dated
  (2026-08-29). Modifications made in vendoring + seeding the catalog:
  - `app/apis/referrals/service.py` — seeded BOLA instances I-06 (`?user_id=`) and
    I-07 (`?username=`).
  - `app/apis/menu/services/update_menu_item_service.py` — seeded BFLA instance I-08
    (role checker commented out).
  - `app/tests/vulns/ave_seed_*.py` — five AVE-added exploit oracles (inverted polarity),
    bound to instances I-04, I-05, I-06, I-07, I-08.
  - Removed upstream's committed `app/.env` (non-secret Postgres defaults, injected by
    `docker-compose`) and stripped `__pycache__`. All other files are upstream verbatim.
  - The catalog of instances → oracles is in [`target/CATALOG.md`](./target/CATALOG.md).
- **Source availability** — the source stays available under GPL-3.0 to recipients.
- **Upstream linkage** — the fork point is pinned to commit `d32d0997…`.
