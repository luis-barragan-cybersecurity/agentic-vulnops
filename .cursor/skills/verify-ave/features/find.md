# LLM finder

`ave find` runs the LLM finder over the inventory, then runs an adversarial cull over every accepted finding. Offline by default both stages replay recorded fixtures. It does not start a model, write a run record, or mutate `README.md` / `target/`. The default fixtures keep all eight accepted findings.

## Sub-features

- `find-help` lists the `find` subcommand and names both stages.
- `find-cli` prints the coverage denominator, one summary per stage, and one block per kept finding.
- `find-offline` replays finder and cull fixtures with no `AVE_LLM_LIVE`.
- `find-cull-contract` proves suppression, fail-open, and bound-oracle override with scripted sessions.
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

- **Help.** Run `.cursor/skills/verify-ave/control-ave capture find-help -- cli -- --help`. Exit code `0`. Stdout lists `find` and says `run the LLM finder and adversarial cull over the inventory (offline fixtures)`.
- **CLI entry.** Run `.cursor/skills/verify-ave/control-ave capture find -- cli -- find`. Exit code `0`.
- **Coverage.** The first line is `find: examined 18 of 27 handlers.`
- **Finder stage.** The next line is `  finder: 8 accepted, 7 finder-cleared, 0 rejected, 0 exhausted.`
- **Cull stage.** The next line is `  adversarial-cull: 8 reviewed, 8 kept, 0 suppressed, 0 fail-open.` The CLI adds a bound-oracle override count only when it is nonzero.
- **Findings.** Stdout has eight kept finding lines, each followed by its rationale. The I-04 location is `0.90 object-ownership-gap   app/apis/orders/services/get_order_service.py:get_order`. Four lines say `object-ownership-gap`. Four say `function-role-gap`. No line starts with `suppressed`.
- **Finder and CLI contracts.** Run `.cursor/skills/verify-ave/control-ave capture find-tests -- pytest -- tests/test_llm_finder.py tests/test_cli.py -q`. Exit code `0`; stdout reports `21 passed` (`19` finder tests and `2` CLI tests).
- **Cull contract.** Run `.cursor/skills/verify-ave/control-ave capture find-cull-tests -- pytest -- tests/test_cull.py -q`. Exit code `0`; stdout reports `29 passed`. Scripted sessions prove validated suppression, fail-open keep, and bound-oracle override. The default CLI fixtures do not exercise those paths.
- **No write.** Run `.cursor/skills/verify-ave/control-ave capture find-tracked-clean -- git diff --exit-code -- README.md target`. Exit code `0`.
- **Proof.** Keep `artifacts/find/`, `artifacts/find-tests/`, `artifacts/find-cull-tests/`, and `artifacts/find-tracked-clean/`.

## Gotchas

- Offline `8 accepted` and `8 kept` are fixture replay. Do not report either number as a live-model result.
- The default fixtures suppress zero and fail-open zero. Use the scripted cull tests to prove suppression, failure, and oracle-override behavior.
- `AVE_LLM_LIVE=1` reaches Anthropic for both stages. Skip that path unless the opt-in and keys are the claim.
- `ave find` does not write `results/runs/`. The in-loop finder and cull run through `ave run`. Prove that through [Run the loop](./run-stub-loop.md).
- The finder and cull read the code-facts store only. `target/catalog.json` is outside the allowlist. Recall tests may read the catalog. The product path must not.
