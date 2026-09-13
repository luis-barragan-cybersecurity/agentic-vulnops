# Route inventory

`ave inventory` parses the allowlisted target application, prints the coverage denominator, and shows the pre-filter screen for each route handler. It does not call a model, start the target, or write a code-facts file.

## Sub-features

- `inventory-help` lists the `inventory` subcommand.
- `inventory-cli` prints one screen for each inventoried route handler.
- `inventory-coverage` reports the handlers found, judged, and dropped before model work.
- `inventory-allowlist` keeps the catalog, target tests, and non-Python files outside the scan.
- `inventory-no-write` leaves `README.md` and `target/` unchanged.

## How to get to it (user POV)

- Run `ave inventory` after `make setup`.
- Run `python -m ave.cli inventory`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- `target/dvrestaurant/app/` exists.
- `git status --porcelain -- README.md target` is empty.

- **Help.** Run `.cursor/skills/verify-ave/control-ave capture inventory-help -- cli -- --help`. Exit code `0`. Stdout lists `inventory`.
- **CLI entry.** Run `.cursor/skills/verify-ave/control-ave capture inventory -- cli -- inventory`. Exit code `0`.
- **Coverage.** The first line is `inventory: examined 18 of 27 handlers.` The next line reports `examine 15, cheap 3, dropped 9`.
- **Handlers.** Stdout has 27 handler lines. The anchor includes `examine`, `GET`, `/orders/{order_id}`, and `get_order`.
- **Contract tests.** Run `.cursor/skills/verify-ave/control-ave capture inventory-tests -- pytest -- tests/test_code_facts.py -q`. Exit code `0`; stdout reports `22 passed`. These tests cover the scan and query contracts, including the writer allowlist.
- **No write.** Run `.cursor/skills/verify-ave/control-ave capture inventory-tracked-clean -- git diff --exit-code -- README.md target`. Exit code `0`.
- **Proof.** Keep `artifacts/inventory/`, `artifacts/inventory-tests/`, and `artifacts/inventory-tracked-clean/`.

## Gotchas

- `examined 18` is the judged denominator. It includes 15 `examine` handlers and three `cheap` handlers. Only nine `drop` handlers are excluded.
- The command does not print or persist a code-facts path.
- `ave run` now consumes this store through the LLM finder. Prove that path with [Run the loop](./run-stub-loop.md). Prove the inspectable model layer with [LLM finder](./find.md).
- There is no `make inventory` target.
- The contract test reads the catalog as its expected answer. The product scan cannot read `target/catalog.json`, `target/CATALOG.md`, or `target/dvrestaurant/app/tests/`.
