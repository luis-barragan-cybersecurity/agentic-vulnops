# Semgrep baseline

`make baseline` scores the role-pattern Semgrep comparator against the vendored authorization catalog. It runs live Semgrep when available, otherwise uses the committed findings, then prints the same precision/recall report and rewrites `results.json`.

## Sub-features

- `baseline-make` runs the comparator through the documented Makefile target.
- `baseline-live` refreshes portable findings when a Semgrep executable is available.
- `baseline-frozen` reproduces the score from committed findings when Semgrep is unavailable.
- `baseline-bar` reports class-aware BOLA recall `0/4` and the precision bar AVE must beat.

## How to get to it (user POV)

- Run `make baseline` from the repo root.
- Run `python evals/baseline/semgrep/score.py` directly when Semgrep is already on `PATH`, `AVE_SEMGREP` points to it, or the committed fallback should be used.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- `evals/baseline/semgrep/semgrep-findings.json` exists if no Semgrep executable is available.
- Record `git status --porcelain -- evals/baseline/semgrep` before the drive. Live Semgrep may refresh the tracked findings; frozen replay should be byte-stable.

- **Make entry.** Run `.cursor/skills/verify-ave/control-ave capture baseline -- make -- baseline`. Exit code `0`.
- **Direct entry.** From the repo root, run `.cursor/skills/verify-ave/control-ave capture baseline-direct -- .venv/bin/python evals/baseline/semgrep/score.py`. It skips the Makefile's install attempt, exits `0`, and reports whether it used live or frozen findings.
- **Score.** Stdout starts with `AVE role-pattern Semgrep baseline — score vs target catalog`, reports `handlers flagged: 6`, and shows class-aware BOLA recall `0%  (0/4)`.
- **Source.** The final line says either `[scored from: live semgrep; wrote results.json]` or `[scored from: frozen semgrep-findings.json; wrote results.json]`.
- **Offline replay.** When Semgrep is absent, run `PIP_NO_INDEX=1 .cursor/skills/verify-ave/control-ave capture baseline-frozen -- make -- baseline`. A failed best-effort install may appear on stderr; the feature passes when scoring still exits `0` from frozen findings.
- **Installed Semgrep.** To exercise frozen replay without uninstalling the venv copy, first confirm `PATH=/usr/bin:/bin command -v semgrep` prints nothing. Then run `.cursor/skills/verify-ave/control-ave capture baseline-frozen -- env -u AVE_SEMGREP PATH=/usr/bin:/bin .venv/bin/python evals/baseline/semgrep/score.py`.
- **Proof.** Keep `artifacts/baseline/stdout.txt` and `exit_code.txt`. Confirm `evals/baseline/semgrep/results.json` contains the printed score. If frozen replay changed either tracked JSON file, record that as drift rather than restoring it.

## Gotchas

- `make baseline` may install Semgrep into the active venv before scoring. Use the frozen replay when network installation is not part of the proof.
- `control-ave` redirects Semgrep's log and settings to `artifacts/.semgrep/`. A bare Semgrep run can fail in a sandbox that cannot write `~/.semgrep`.
- This is the pattern-scanner comparator, not `ave scoreboard`. It does not update the README results table.
- The generous location score gives I-02 credit for overlap. The class-aware score counts I-02 as a wrong-class false positive and keeps BOLA recall at `0/4`.
- CI does not run `make baseline` today. The committed findings make the score reproducible, but the workflow has no baseline job.
