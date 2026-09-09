"""AVE command-line entrypoint.

Backs the Makefile verbs and the `ave` console script.

  ave run         -> walk the seven-phase graph on one seeded instance, write artifacts
  ave break       -> report the semantic flaws already seeded in the target (demo step 1)
  ave eradicate   -> break -> run -> HITL approve -> PR (demo steps 1-3)
  ave scoreboard  -> regenerate the results table from run records (demo step 4)
  ave inventory   -> the deterministic find-stage inventory + coverage denominator

The walking skeleton (ticket 03) makes `run` real end to end: it walks all seven phases
and writes a run record + PR bundle under `results/runs/<id>/`. Ticket 04 pointed the pack
at the real vendored target (`target/catalog.json`, 8 authorization instances). `run`
drives the one instance the pack declares, the anchor I-04, on a hermetic oracle; the
other seven stay ground truth for scoring. The HITL gate is in the graph; the CLI
auto-approves and does not pause. `break` and `scoreboard` stay thin until the
metrics/schema work (ticket 05).
"""

from __future__ import annotations

import argparse
import os

from ave.policy.loader import policy_version
from ave.runner import persist_run, run_once
from ave.state import AVEState
from ave.telemetry import setup_tracing


def _pinned_env_opt_in() -> bool:
    return os.environ.get("AVE_PINNED_ENV", "").strip().lower() in ("1", "true", "yes")


def initial_run_state() -> AVEState:
    initial: AVEState = {
        "target_ref": "target/dvrestaurant@d32d0997",
        "policy_version": policy_version(),
    }
    if _pinned_env_opt_in():
        initial["use_pinned_env"] = True
    return initial


def _run(_: argparse.Namespace) -> int:
    tracer = setup_tracing()
    with tracer.start_as_current_span("ave.run"):
        initial = initial_run_state()
        print("run: walking seven phases; HITL gate auto-approves (no pause).")
        final = run_once(initial, auto_approve=True)
        artifacts = persist_run(final)
    print("run complete.")
    print(f"  human_approved = {final.get('human_approved')}")
    print(f"  ready_to_merge = {final.get('ready_to_merge')}")
    print(f"  pr_ref         = {final.get('pr_ref')}")
    for name, path in artifacts.items():
        print(f"  {name:11} -> {path}")
    return 0


def _break(_: argparse.Namespace) -> int:
    print("break: the vendored target already carries the seeded catalog (target/CATALOG.md,")
    print("       8 authorization instances + decoys). `run` drives the BOLA anchor (I-04).")
    return 0


def _eradicate(args: argparse.Namespace) -> int:
    _break(args)
    print("eradicate: break then run. HITL gate auto-approves (no pause).")
    return _run(args)


def _scoreboard(_: argparse.Namespace) -> int:
    print("scoreboard: would regenerate the results table from run records (ticket 05).")
    return 0


def _inventory(_: argparse.Namespace) -> int:
    """Show the deterministic find-stage inventory: the coverage denominator and each route
    handler's pre-filter screen. No model is involved — this is the evidence layer the LLM
    finder (ticket 25) reasons over, made inspectable on its own (ticket 23)."""
    from ave.adapters.python_authz.code_facts import CodeFactsStore

    store = CodeFactsStore.build()
    coverage = store.coverage()
    print(f"inventory: {coverage.summary()}.")
    print(
        f"  examine {coverage.by_screen['examine']}, "
        f"cheap {coverage.by_screen['cheap']}, "
        f"dropped {coverage.by_screen['drop']} (by arithmetic, before any model call)."
    )
    for record in store.inventory.handlers:
        result = store.screen_of(record.handler_id)
        print(f"  {result.screen:8} {record.method:6} {record.path:32} {record.symbol}")
    return 0


def _find(_: argparse.Namespace) -> int:
    """Run the pack-owned find operation and show what it rediscovered (ticket 25/26).

    This is the same `LanguagePack.find()` path Match walks. Offline by default — the
    finder replays recorded transcripts, so this needs no model access — and
    citation-validated at the submission boundary. Set `AVE_LLM_LIVE=1` to reach the
    live model instead of the fixtures."""
    from ave.adapters import get_default_pack

    batch = get_default_pack().find(str(initial_run_state().get("target_ref", "unset")))
    coverage = batch.report.get("coverage")
    if isinstance(coverage, dict) and coverage.get("summary"):
        print(f"find: {coverage['summary']}.")
    print(
        f"  {len(batch.kept)} findings, {batch.report.get('cleared', 0)} cleared, "
        f"{batch.report.get('rejected', 0)} rejected verdicts "
        "(rejected, not down-weighted)."
    )
    if batch.suppressed:
        print(f"  {len(batch.suppressed)} suppressed by adversarial cull.")
    for finding in batch.kept:
        evidence = finding.get("evidence", {})
        kind = str(finding.get("kind", ""))
        print(
            f"  {float(finding.get('confidence', 0.0)):.2f} "
            f"{kind:22} {finding.get('location')}"
        )
        rationale = evidence.get("rationale", "") if isinstance(evidence, dict) else ""
        if rationale:
            print(f"       {rationale}")
    for finding in batch.suppressed:
        print(f"  suppressed {finding.get('id')} {finding.get('location')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ave", description="Autonomous Vulnerability Eradication."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, help_text in (
        ("run", _run, "walk the seven-phase graph on one seeded instance, write artifacts"),
        ("break", _break, "report the semantic flaws already seeded in the target"),
        ("eradicate", _eradicate, "break -> run -> HITL approve -> PR (demo)"),
        ("scoreboard", _scoreboard, "regenerate the results table from run records"),
        ("inventory", _inventory, "deterministic find-stage inventory + coverage"),
        ("find", _find, "run the LLM finder over the inventory (offline fixtures)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(handler=handler)

    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
