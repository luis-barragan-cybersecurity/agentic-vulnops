# LLM finder

`ave find` runs the LLM finder over the inventory and prints what it rediscovered. Offline by default it replays recorded fixtures. It does not start a model, write a run record, or mutate `README.md` / `target/`.

## Sub-features

- `find-help` lists the `find` subcommand.
- `find-cli` prints the coverage denominator, the finding and cleared counts, and one line per finding.
- `find-offline` replays fixtures with no `AVE_LLM_LIVE`.
- `find-no-write` leaves `README.md` and `target/` unchanged.

## How to get to it (user POV)

- Run `ave find` after `make setup`.
- Run `python -m ave.cli find`.
- There is no `make find` target.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- `AVE_LLM_LIVE` is unset. Do not set it unless you are proving the live-model opt-in and keys exist.
- `git status --porcelain -- README.md target` is empty.

- **Help.** Run `.cursor/skills/verify-ave/control-ave capture find-help -- cli -- --help`. Exit code `0`. Stdout lists `find` and says `run the LLM finder over the inventory (offline fixtures)`.
- **CLI entry.** Run `.cursor/skills/verify-ave/control-ave capture find -- cli -- find`. Exit code `0`.
- **Coverage.** The first line is `find: examined 18 of 27 handlers.`
- **Counts.** The next line is `8 findings, 7 cleared, 0 rejected verdicts (rejected, not down-weighted).`
- **Findings.** Stdout has eight finding lines. The I-04 location is `0.90 object-ownership-gap   app/apis/orders/services/get_order_service.py:get_order`. Four lines say `object-ownership-gap`. Four say `function-role-gap`.
- **Contract tests.** Run `.cursor/skills/verify-ave/control-ave capture find-tests -- pytest -- tests/test_llm_finder.py -q`. Exit code `0`; stdout reports `14 passed`. These tests lock fixture recall, decoy clears, citation rejection, and allowlist isolation. They are not live-model proof.
- **No write.** Run `.cursor/skills/verify-ave/control-ave capture find-tracked-clean -- git diff --exit-code -- README.md target`. Exit code `0`.
- **Proof.** Keep `artifacts/find/`, `artifacts/find-tests/`, and `artifacts/find-tracked-clean/`.

## Gotchas

- Offline `8 findings` is fixture replay. The recorded transcripts are the default client. Do not report that number as a live-model result.
- `AVE_LLM_LIVE=1` reaches Anthropic. Skip that path unless the opt-in and keys are the claim.
- `ave find` does not write `results/runs/`. The in-loop finder is `ave run`. Prove that through [Run the loop](./run-stub-loop.md).
- The finder reads the code-facts store only. `target/catalog.json` is outside the allowlist. Recall tests may read the catalog. The product path must not.
- There is no `make find` target.
