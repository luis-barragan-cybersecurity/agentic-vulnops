# Adversarial cull

`ave find` runs one adversarial review for every finding that the LLM finder accepts. Each review starts with a fresh context and tries to show that the finding is legitimate. A validated suppress removes the finding before ranking. Invalid or unavailable reviews fail open and keep it. A bound oracle overrides a submitted suppress. The default offline fixtures review and keep all eight findings, so tests provide the suppression and failure-path proof.

## Sub-features

- `cull-cli` prints reviewed, kept, suppressed, and fail-open counts after the finder summary.
- `cull-isolation` opens one fresh session per accepted finding and withholds oracle, catalog, confidence, other candidates, and previous verdicts.
- `cull-boundary` validates finding identity, stance, hypotheses, and source citations before a review can suppress.
- `cull-fail-open` keeps findings when a review is missing, exhausted, malformed, unavailable, or interrupted by a session error.
- `cull-oracle` records a submitted suppress but keeps a finishable finding (`pack.can_drive`). That is get_order plus an object-ownership gap plus a handler route, not a catalog oracle path.
- `cull-pairing` pairs candidates and reviews one-to-one without collapsing duplicate identities.
- `cull-lifecycle` stores suppressed findings as false positives triaged at Match completion.
- `cull-cleared` projects validated ruled-out hypotheses into GFM-safe PR table rows.
- `cull-recording` separates live cull recordings under `llm_cull/`.
- `cull-fixtures` regenerates eight deterministic offline transcripts.

## How to get to it (user POV)

- Run `ave find` or `python -m ave.cli find` to inspect the finder and cull summaries.
- Run `ave run`, `python -m ave.cli run`, or `make run` to persist the cull ledger and Cleared row.
- Run `python -m evals.fixtures.gen_llm_cull_fixtures` to regenerate offline cull fixtures.
- There is no `ave cull`, `make cull`, or `make find` command.

## Driving it with control-ave

Preconditions:

- `.cursor/skills/verify-ave/control-ave doctor` succeeded.
- `AVE_LLM_LIVE`, `AVE_LLM_RECORD`, and `AVE_PINNED_ENV` are unset.
- `git status --porcelain -- README.md target` is empty.

- **Direct CLI.** Run `.cursor/skills/verify-ave/control-ave capture cull-find -- cli -- find`. Exit code `0`. Stdout starts with `find: examined 18 of 27 handlers.`, then `  finder: 8 accepted, 7 finder-cleared, 0 rejected, 0 exhausted.`, then `  adversarial-cull: 8 reviewed, 8 kept, 0 suppressed, 0 fail-open.` This proves default fixture orchestration and the keep path. It does not prove model quality or a suppression.
- **Cull contracts.** Run `.cursor/skills/verify-ave/control-ave capture cull-tests -- pytest -- tests/test_cull.py -q`. Exit code `0`; stdout reports `29 passed`. The file proves fresh empty sessions, redaction before transport, strict citations, all fail-open bases, terminal ambiguity rejection, validated suppression, bound-oracle override, and strict one-to-one pairing.
- **Tool separation.** Run `.cursor/skills/verify-ave/control-ave capture cull-tools -- pytest -- tests/test_retrieval_tools.py -q`. Exit code `0`; stdout reports `5 passed`. Finder tools include `list_candidates`. Cull tools omit and reject it.
- **Recording namespace.** Run `.cursor/skills/verify-ave/control-ave capture cull-model -- pytest -- tests/test_model.py::test_cull_terminal_live_session_writes_under_namespaced_root -q`. Exit code `0`; stdout reports `1 passed`. Anthropic is stubbed. The test proves that cull records go under `$AVE_LLM_RECORD/llm_cull/`, separate from finder records.
- **Run ledger.** Run `.cursor/skills/verify-ave/control-ave capture cull-run -- cli -- run`. Exit code `0`. Open the printed run record. Match has `suppressed: 0`. Its `find_stage.cull` object has `reviewed: 8`, `kept: 8`, `suppressed: 0`, `fail_open: 0`, `bound_oracle_overrides: 0`, `client: "fixture"`, both prompt versions at `2`, and eight validated keep reviews.
- **Suppressed lifecycle.** Run `.cursor/skills/verify-ave/control-ave capture cull-many -- pytest -- tests/test_many_findings.py -q`. Exit code `0`; stdout reports `28 passed`. `test_suppressed_findings_are_false_positives_triaged_at_match` proves that a suppressed finding is absent from the ranked findings, has `outcome: "false_positive"`, and has `triaged_at` equal to Match completion. The default run suppresses zero.
- **Cleared table.** Run `.cursor/skills/verify-ave/control-ave capture cull-pr-body -- pytest -- tests/test_pr_body.py -q`. Exit code `0`; stdout reports `24 passed`. The tests prove that the pack projects the selected finding's validated ruled-out hypothesis into Cleared, preserves inclusive citation ranges, renders honest-empty output when no row exists, and escapes model-authored GFM table content.
- **Fixture regeneration.** Run `.venv/bin/python -m evals.fixtures.gen_llm_cull_fixtures`, then `git diff --exit-code -- src/ave/adapters/python_authz/fixtures/llm_cull`. The generator reports eight fixtures and the diff exits `0`. It replays finder fixtures and does not call a live model.
- **Invariant limitation.** Run `.cursor/skills/verify-ave/control-ave capture cull-invariant -- invariant -- --check`. Stdout remains `invariant: OK (no run records to validate yet)`, even after a run writes records. Do not report this as cull-ledger validation.
- **Tracked-file safety.** Run `.cursor/skills/verify-ave/control-ave capture cull-tracked-clean -- git diff --exit-code -- README.md target`. Exit code `0`.

## Gotchas

- Offline `8 reviewed, 8 kept` is fixture replay. All committed cull fixtures submit `keep`.
- Default fixtures do not exercise suppression, fail-open, or oracle override. Use the named contract tests.
- `AVE_LLM_LIVE=1` reaches Anthropic for both the finder and the cull. Do not set it for this recipe.
- Fail-open keeps a finding. A malformed review cannot suppress.
- A redaction leak aborts before `ModelClient.begin`; it does not fail open.
- Pair-count mismatch raises instead of failing open because it indicates an internal orchestration defect.
- Only the object-ownership finding at the I-04 location receives the bound oracle. A role-gap finding at that location is neither protected nor drivable.
- `ave run` does not print the cull summary. Read it from the Match span.
- The invariant command does not load `results/runs/`.
