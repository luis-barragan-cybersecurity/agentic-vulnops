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

### GPL-3.0 obligations honored when the fork is vendored in-repo

The target fork is scaffolded to live under [`target/`](./target/). When it is vendored
(ticket 04), the following obligations apply and are why this repo carries the GPL-3.0
`LICENSE`:

- **Copyleft** — a distributed modified fork is itself GPL-3.0; the verbatim GPL-3.0
  `LICENSE` is retained.
- **Notices & attribution** — upstream copyright/author notices are preserved; theowni /
  the upstream repo is credited here and in the README.
- **State changes (GPL-3.0 §5)** — every file AVE modifies (e.g. seeded authorization
  instances) is marked as changed and dated.
- **Source availability** — the source stays available under GPL-3.0 to recipients.
- **Upstream linkage** — the fork point is pinned to commit `d32d0997…`.
